/// Test mode — probe DNS resolvers with a live TUI dashboard.
///
/// Reads resolver IPs from a text file (one per line, `#` comments allowed),
/// spawns concurrent worker threads, and displays results in three panels:
///
///   ┌── Progress ──────────┬── Leaderboard ──────┐
///   │ probes / gauge / ETA │ IPs ranked by RTT   │
///   ├── Log ───────────────┴─────────────────────┤
///   │ scrollable raw probe output                │
///   └────────────────────────────────────────────┘
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
use ratatui::Terminal;

use crate::config::TestConfig;

// ── constants ─────────────────────────────────────────────────────────────────

const PROTOCOL_VERSION: u32 = 0x00000502;

const QTYPES: &[(&str, u16)] = &[
    ("NULL", 10),
    ("PRIVATE", 65399),
    ("TXT", 16),
    ("SRV", 33),
    ("MX", 15),
    ("CNAME", 5),
    ("A", 1),
];

const DNS_PORT: u16 = 53;
const CSV_PATH: &str = "results.csv";
const B32_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

// ── DNS wire helpers ──────────────────────────────────────────────────────────

fn b32_enc_5(v: u8) -> u8 {
    B32_ALPHA[(v & 0x1f) as usize]
}

fn build_version_hostname(data: &[u8; 6], topdomain: &str) -> String {
    let mut encoded = [0u8; 10];
    let bits: u64 = (data[0] as u64) << 40
        | (data[1] as u64) << 32
        | (data[2] as u64) << 24
        | (data[3] as u64) << 16
        | (data[4] as u64) << 8
        | (data[5] as u64);
    for (i, slot) in encoded.iter_mut().enumerate() {
        *slot = b32_enc_5(((bits >> (45 - i * 5)) & 0x1f) as u8);
    }
    format!(
        "v{}.aaa.{}",
        std::str::from_utf8(&encoded).unwrap(),
        topdomain
    )
}

fn build_dns_query(hostname: &str, qtype: u16, query_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(256);
    pkt.extend_from_slice(&query_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR = 0
    for label in hostname.split('.') {
        if label.is_empty() {
            continue;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    pkt
}

fn extract_answer(resp: &[u8], qtype: u16) -> Option<Vec<u8>> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    pos = skip_name(resp, pos)?;
    pos += 4; // QTYPE + QCLASS

    if pos >= resp.len() {
        return None;
    }

    pos = skip_name(resp, pos)?;
    if pos + 10 > resp.len() {
        return None;
    }
    let ans_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    pos += 8; // type + class + ttl
    let rdlen = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
    pos += 2;

    if pos + rdlen > resp.len() {
        return None;
    }
    let rdata = &resp[pos..pos + rdlen];

    match (qtype, ans_type) {
        (10, _) | (65399, _) => Some(rdata.to_vec()),
        (16, 16) => {
            if rdata.is_empty() {
                return None;
            }
            let txt_len = rdata[0] as usize;
            if 1 + txt_len > rdata.len() {
                return None;
            }
            Some(rdata[1..1 + txt_len].to_vec())
        }
        (5, 5) | (1, 5) => {
            let name = read_name(resp, pos)?;
            Some(name.into_bytes())
        }
        (15, 15) => {
            if rdlen < 3 {
                return None;
            }
            let name = read_name(resp, pos + 2)?;
            Some(name.into_bytes())
        }
        (33, 33) => {
            if rdlen < 7 {
                return None;
            }
            let name = read_name(resp, pos + 6)?;
            Some(name.into_bytes())
        }
        _ => None,
    }
}

fn decode_iodine_payload(raw: &[u8], qtype: u16) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }
    if qtype == 10 || qtype == 65399 {
        return Some(raw.to_vec());
    }
    let tag = raw[0].to_ascii_uppercase();
    let rest: Vec<u8> = raw[1..].iter().filter(|&&b| b != b'.').copied().collect();
    match tag {
        b'H' | b'T' => base32_decode_iodine(&rest),
        b'I' | b'S' => base64_decode_simple(&rest),
        b'R' => Some(rest),
        _ => base32_decode_iodine(&rest),
    }
}

fn base32_decode_iodine(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &c in input {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => continue,
        };
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn base64_decode_simple(input: &[u8]) -> Option<Vec<u8>> {
    let s: Vec<u8> = input
        .iter()
        .filter(|&&b| b != b'\n' && b != b'\r')
        .copied()
        .collect();
    let padded = match s.len() % 4 {
        0 => s,
        2 => {
            let mut v = s;
            v.extend_from_slice(b"==");
            v
        }
        3 => {
            let mut v = s;
            v.push(b'=');
            v
        }
        _ => return None,
    };
    let mut out = Vec::new();
    for chunk in padded.chunks(4) {
        let d = |b: u8| -> Option<u8> {
            match b {
                b'A'..=b'Z' => Some(b - b'A'),
                b'a'..=b'z' => Some(b - b'a' + 26),
                b'0'..=b'9' => Some(b - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(0),
                _ => None,
            }
        };
        let a = d(chunk[0])?;
        let b = d(chunk[1])?;
        let c = d(chunk[2])?;
        let dd = d(chunk[3])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 2) | dd);
        }
    }
    Some(out)
}

fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

fn read_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut safety = 0usize;
    loop {
        if pos >= data.len() || safety > 128 {
            return None;
        }
        safety += 1;
        let len = data[pos];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                jumped = true;
            }
            pos = (((len & 0x3f) as usize) << 8) | data[pos + 1] as usize;
            continue;
        }
        pos += 1;
        if pos + len as usize > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len as usize]).to_string());
        pos += len as usize;
    }
    Some(labels.join("."))
}

// ── result types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum VersionOutcome {
    Vack,
    Vnak,
    Vfull,
    NoReply,
    DecodeError,
    SendError(String),
}

#[derive(Debug, Clone)]
struct ProbeResult {
    resolver: String,
    qtype_name: &'static str,
    outcome: VersionOutcome,
    rtt: Option<Duration>,
}

// ── TUI application state ─────────────────────────────────────────────────────

struct App {
    total: usize,
    completed: usize,
    start: Instant,
    best_rtt: HashMap<String, Duration>,
    leaderboard: Vec<(String, Duration)>,
    results: Vec<ProbeResult>,
    logs: Vec<String>,
    log_offset: u16,
    done: bool,
    workers: usize,
    topdomain: String,
}

impl App {
    fn new(total: usize, workers: usize, topdomain: String) -> Self {
        Self {
            total,
            completed: 0,
            start: Instant::now(),
            best_rtt: HashMap::new(),
            leaderboard: Vec::new(),
            results: Vec::new(),
            logs: Vec::new(),
            log_offset: 0,
            done: false,
            workers,
            topdomain,
        }
    }

    fn push_result(&mut self, r: ProbeResult) {
        let status_str = match &r.outcome {
            VersionOutcome::Vack => {
                let ms = r.rtt.unwrap_or_default().as_secs_f64() * 1000.0;
                format!("VACK  {ms:.0}ms")
            }
            VersionOutcome::Vnak => "VNAK".into(),
            VersionOutcome::Vfull => "VFULL".into(),
            VersionOutcome::NoReply => "no reply".into(),
            VersionOutcome::DecodeError => "decode error".into(),
            VersionOutcome::SendError(e) => format!("error: {e}"),
        };
        self.logs.push(format!(
            "{:<18} {:<8} {}",
            r.resolver, r.qtype_name, status_str
        ));

        if matches!(r.outcome, VersionOutcome::Vack) {
            if let Some(rtt) = r.rtt {
                let entry = self.best_rtt.entry(r.resolver.clone()).or_insert(rtt);
                if rtt < *entry {
                    *entry = rtt;
                }
                let mut lb: Vec<_> = self.best_rtt.iter().map(|(k, v)| (k.clone(), *v)).collect();
                lb.sort_by_key(|(_, d)| *d);
                self.leaderboard = lb;
            }
        }

        self.results.push(r);
        self.completed += 1;
        if self.completed >= self.total {
            self.done = true;
        }
    }

    fn ratio(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.completed as f64 / self.total as f64
    }

    fn eta(&self) -> Option<Duration> {
        if self.completed == 0 || self.done {
            return None;
        }
        let elapsed = self.start.elapsed();
        let rate = self.completed as f64 / elapsed.as_secs_f64();
        if rate <= 0.0 {
            return None;
        }
        let remaining = (self.total - self.completed) as f64 / rate;
        Some(Duration::from_secs_f64(remaining))
    }
}

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h {:02}m {:02}s", s / 3600, (s % 3600) / 60, s % 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

pub async fn run(cfg: TestConfig) -> Result<()> {
    run_tui(cfg)
}

fn read_resolvers(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read resolvers file '{}': {}", path, e))?;
    let resolvers: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if resolvers.is_empty() {
        anyhow::bail!("no resolvers found in '{}'", path);
    }
    Ok(resolvers)
}

fn run_tui(cfg: TestConfig) -> Result<()> {
    let resolvers = read_resolvers(&cfg.resolvers_file)?;
    let num_workers = cfg.workers.unwrap_or(8);
    let topdomain = extract_topdomain(&cfg.iodine_args)
        .ok_or_else(|| anyhow::anyhow!("could not find topdomain in iodine_args"))?;
    let timeout = Duration::from_secs(cfg.ping_timeout_secs);

    let mut tasks: Vec<(String, &'static str, u16)> = Vec::new();
    for resolver in &resolvers {
        for &(qtype_name, qtype) in QTYPES {
            tasks.push((resolver.clone(), qtype_name, qtype));
        }
    }
    let total = tasks.len();
    let tasks = Arc::new(tasks);
    let next_idx = Arc::new(AtomicUsize::new(0));

    let (tx, rx) = std::sync::mpsc::channel::<ProbeResult>();

    let actual_workers = num_workers.min(total).max(1);
    for _ in 0..actual_workers {
        let tasks = tasks.clone();
        let next = next_idx.clone();
        let tx = tx.clone();
        let td = topdomain.clone();
        std::thread::spawn(move || loop {
            let idx = next.fetch_add(1, Ordering::Relaxed);
            if idx >= tasks.len() {
                break;
            }
            let (ref resolver, qtype_name, qtype) = tasks[idx];
            let result = probe_version(resolver, &td, qtype, qtype_name, timeout);
            if tx.send(result).is_err() {
                break;
            }
        });
    }
    drop(tx);

    // Panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(total, actual_workers, topdomain);
    let tick = Duration::from_millis(33); // ~30 fps

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.log_offset = app.log_offset.saturating_add(3);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.log_offset = app.log_offset.saturating_sub(3);
                        }
                        KeyCode::Enter if app.done => break,
                        _ => {}
                    }
                }
            }
        }

        loop {
            match rx.try_recv() {
                Ok(result) => app.push_result(result),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.done = true;
                    break;
                }
            }
        }

        if app.done {
            terminal.draw(|f| ui(f, &app))?;
            loop {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter => break,
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.log_offset = app.log_offset.saturating_add(3);
                                terminal.draw(|f| ui(f, &app))?;
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.log_offset = app.log_offset.saturating_sub(3);
                                terminal.draw(|f| ui(f, &app))?;
                            }
                            _ => {}
                        }
                    }
                }
            }
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Post-TUI summary
    println!(
        "\nProbed {} resolvers × {} types = {} probes in {}",
        resolvers.len(),
        QTYPES.len(),
        total,
        fmt_dur(app.start.elapsed()),
    );
    if let Some((ip, rtt)) = app.leaderboard.first() {
        println!("Best: {} ({:.0}ms)", ip, rtt.as_secs_f64() * 1000.0,);
    }
    write_csv(&app.results)?;
    Ok(())
}

// ── rendering ─────────────────────────────────────────────────────────────────

fn ui(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(6)])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    ui_progress(f, app, top[0]);
    ui_leaderboard(f, app, top[1]);
    ui_logs(f, app, rows[1]);
}

fn ui_progress(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" ◈ ", Style::default().fg(Color::Cyan)),
            Span::styled(
                "Progress ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 3 {
        return;
    }

    let elapsed = fmt_dur(app.start.elapsed());
    let eta_str = app
        .eta()
        .map(|d| format!("~{}", fmt_dur(d)))
        .unwrap_or_else(|| {
            if app.done {
                "done".into()
            } else {
                "…".into()
            }
        });
    let pct = (app.ratio() * 100.0) as u16;
    let vack_count = app.leaderboard.len();

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    let line0 = Line::from(vec![
        Span::styled(" Probes  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}/{}", app.completed, app.total),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let line1 = Line::from(vec![
        Span::styled(" Domain  ", Style::default().fg(Color::DarkGray)),
        Span::styled(&app.topdomain, Style::default().fg(Color::Magenta)),
        Span::styled(
            format!("   {} IPs responded", vack_count),
            Style::default().fg(Color::Green),
        ),
    ]);

    let line2 = Line::from(vec![
        Span::styled(
            format!(" Workers {:<4}", app.workers),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!(" Elapsed {:<10}", elapsed),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(" ETA ", Style::default().fg(Color::DarkGray)),
        Span::styled(eta_str, Style::default().fg(Color::Yellow)),
    ]);

    f.render_widget(Paragraph::new(line0), parts[0]);
    f.render_widget(Paragraph::new(line1), parts[1]);
    f.render_widget(Paragraph::new(Line::raw("")), parts[2]);
    f.render_widget(Paragraph::new(line2), parts[3]);

    let gauge_area = Rect {
        x: parts[4].x + 1,
        y: parts[4].y,
        width: parts[4].width.saturating_sub(2),
        height: 1,
    };
    let color = if app.done { Color::Green } else { Color::Cyan };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(color).bg(Color::DarkGray))
        .ratio(app.ratio().min(1.0))
        .label(format!("{pct}%"));
    f.render_widget(gauge, gauge_area);
}

fn ui_leaderboard(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" ★ ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Leaderboard ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.leaderboard.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            " waiting for results…",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
        f.render_widget(msg, inner);
        return;
    }

    let max_items = inner.height as usize;
    let items: Vec<ListItem> = app
        .leaderboard
        .iter()
        .take(max_items)
        .enumerate()
        .map(|(i, (ip, rtt))| {
            let ms = rtt.as_secs_f64() * 1000.0;
            let rank_color = match i {
                0 => Color::Yellow,
                1 => Color::White,
                2 => Color::Rgb(205, 127, 50),
                _ => Color::DarkGray,
            };
            let rtt_color = if ms < 50.0 {
                Color::Green
            } else if ms < 150.0 {
                Color::Yellow
            } else {
                Color::Red
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:>2}. ", i + 1),
                    Style::default().fg(rank_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{:<20}", ip), Style::default().fg(Color::White)),
                Span::styled(format!("{:>6.0}ms", ms), Style::default().fg(rtt_color)),
            ]))
        })
        .collect();

    f.render_widget(List::new(items), inner);
}

fn ui_logs(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let title = if app.done {
        Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(Color::Green)),
            Span::styled(
                "Complete ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("— press q to exit ", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ▸ ", Style::default().fg(Color::Cyan)),
            Span::styled(
                "Log ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("↑/↓ scroll ", Style::default().fg(Color::DarkGray)),
        ])
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.logs.is_empty() {
        return;
    }

    let visible = inner.height as usize;
    let total = app.logs.len();
    let offset = app.log_offset as usize;

    let end = total.saturating_sub(offset);
    let start = end.saturating_sub(visible);

    let items: Vec<ListItem> = app.logs[start..end]
        .iter()
        .map(|line| {
            let style = if line.contains("VACK") {
                Style::default().fg(Color::Green)
            } else if line.contains("VNAK") || line.contains("VFULL") {
                Style::default().fg(Color::Yellow)
            } else if line.contains("error") || line.contains("no reply") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(Span::styled(format!("  {line}"), style)))
        })
        .collect();

    f.render_widget(List::new(items), inner);
}

// ── DNS probe ─────────────────────────────────────────────────────────────────

fn probe_version(
    resolver: &str,
    topdomain: &str,
    qtype: u16,
    qtype_name: &'static str,
    timeout: Duration,
) -> ProbeResult {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult {
                resolver: resolver.to_owned(),
                qtype_name,
                outcome: VersionOutcome::SendError(e.to_string()),
                rtt: None,
            };
        }
    };
    let _ = sock.set_read_timeout(Some(timeout));

    let dst: SocketAddr = format!("{resolver}:{DNS_PORT}")
        .parse()
        .unwrap_or_else(|_| SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT));

    let seed = rand_u16();
    let mut payload = [0u8; 6];
    payload[0] = (PROTOCOL_VERSION >> 24) as u8;
    payload[1] = (PROTOCOL_VERSION >> 16) as u8;
    payload[2] = (PROTOCOL_VERSION >> 8) as u8;
    payload[3] = PROTOCOL_VERSION as u8;
    payload[4] = (seed >> 8) as u8;
    payload[5] = seed as u8;

    let hostname = build_version_hostname(&payload, topdomain);
    let query_id = rand_u16();
    let pkt = build_dns_query(&hostname, qtype, query_id);

    let t0 = Instant::now();
    if let Err(e) = sock.send_to(&pkt, dst) {
        return ProbeResult {
            resolver: resolver.to_owned(),
            qtype_name,
            outcome: VersionOutcome::SendError(e.to_string()),
            rtt: None,
        };
    }

    let mut buf = [0u8; 4096];
    let rtt;
    let outcome = loop {
        match sock.recv_from(&mut buf) {
            Err(_) => {
                rtt = None;
                break VersionOutcome::NoReply;
            }
            Ok((n, _)) => {
                let resp = &buf[..n];
                if n < 2 || u16::from_be_bytes([resp[0], resp[1]]) != query_id {
                    continue;
                }
                rtt = Some(t0.elapsed());
                let Some(raw) = extract_answer(resp, qtype) else {
                    break VersionOutcome::DecodeError;
                };
                let Some(decoded) = decode_iodine_payload(&raw, qtype) else {
                    break VersionOutcome::DecodeError;
                };
                if decoded.len() >= 4 {
                    if &decoded[..4] == b"VACK" {
                        break VersionOutcome::Vack;
                    } else if &decoded[..4] == b"VNAK" {
                        break VersionOutcome::Vnak;
                    } else if &decoded[..4] == b"VFUL" {
                        break VersionOutcome::Vfull;
                    }
                }
                break VersionOutcome::DecodeError;
            }
        }
    };

    ProbeResult {
        resolver: resolver.to_owned(),
        qtype_name,
        outcome,
        rtt,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn rand_u16() -> u16 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    COUNTER.fetch_add(1, Ordering::Relaxed).hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut h);
    h.finish() as u16
}

fn extract_topdomain(args: &[String]) -> Option<String> {
    let mut bare: Vec<&str> = Vec::new();
    let flags_with_value: &[&str] = &[
        "-u", "-t", "-d", "-R", "-m", "-M", "-T", "-O", "-L", "-I", "-P", "-z", "-F",
    ];
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if flags_with_value.iter().any(|&f| arg == f) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        if arg == "RESOLVER" {
            continue;
        }
        bare.push(arg.as_str());
    }
    match bare.len() {
        0 => None,
        1 => Some(bare[0].to_owned()),
        _ => Some(bare[bare.len() - 1].to_owned()),
    }
}

// ── CSV output ────────────────────────────────────────────────────────────────

fn write_csv(results: &[ProbeResult]) -> Result<()> {
    let mut f = std::fs::File::create(CSV_PATH)?;
    writeln!(f, "resolver,qtype,rtt_ms,status")?;
    for r in results {
        let rtt_ms = r
            .rtt
            .map(|d| format!("{:.3}", d.as_secs_f64() * 1000.0))
            .unwrap_or_default();
        let status = match &r.outcome {
            VersionOutcome::Vack => "vack".into(),
            VersionOutcome::Vnak => "vnak".into(),
            VersionOutcome::Vfull => "vfull".into(),
            VersionOutcome::NoReply => "no_reply".into(),
            VersionOutcome::DecodeError => "decode_error".into(),
            VersionOutcome::SendError(e) => format!("send_error: {}", e.replace(',', ";")),
        };
        writeln!(f, "{},{},{},{}", r.resolver, r.qtype_name, rtt_ms, status)?;
    }
    println!("Results saved to {CSV_PATH}");
    Ok(())
}
