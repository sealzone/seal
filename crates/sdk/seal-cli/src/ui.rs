//! Terminal output: color (only on a terminal, never with `NO_COLOR`, `CLICOLOR=0` or
//! `--no-color`), the Seal mark, aligned tables, a spinner while waiting, and prompts (only
//! when stdin and stderr are terminals; scripts get an error naming the missing flag).

use std::io::{IsTerminal as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

use anstyle::{AnsiColor, Color, RgbColor, Style};

/// Seal red, #e5402f.
const SEAL_RED: RgbColor = RgbColor(0xe5, 0x40, 0x2f);

static COLOR: AtomicBool = AtomicBool::new(false);
static TRUECOLOR: AtomicBool = AtomicBool::new(false);
/// Messages go to stderr: stdout carries a key or a blob.
static STDOUT_RESERVED: AtomicBool = AtomicBool::new(false);

/// Decides color once, before any output.
pub fn init(no_color: bool) {
    let off = no_color
        || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
        || std::env::var("CLICOLOR").is_ok_and(|v| v == "0")
        || std::env::var("TERM").is_ok_and(|t| t == "dumb");
    COLOR.store(!off && std::io::stdout().is_terminal(), Ordering::Relaxed);
    TRUECOLOR.store(std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit"), Ordering::Relaxed);
}

pub fn color() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// From now on, `say!` writes to stderr.
pub fn reserve_stdout() {
    STDOUT_RESERVED.store(true, Ordering::Relaxed);
}

pub fn stdout_reserved() -> bool {
    STDOUT_RESERVED.load(Ordering::Relaxed)
}

pub fn red() -> Style {
    if TRUECOLOR.load(Ordering::Relaxed) {
        Style::new().fg_color(Some(Color::Rgb(SEAL_RED)))
    } else {
        Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red)))
    }
}

fn paint(style: Style, text: &str) -> String {
    if color() {
        format!("{}{text}{}", style.render(), style.render_reset())
    } else {
        text.to_string()
    }
}

pub fn accent(text: &str) -> String {
    paint(red(), text)
}
pub fn bold(text: &str) -> String {
    paint(Style::new().bold(), text)
}
pub fn dim(text: &str) -> String {
    paint(Style::new().dimmed(), text)
}
pub fn green(text: &str) -> String {
    paint(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))), text)
}
pub fn yellow(text: &str) -> String {
    paint(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))), text)
}

/// A green check mark and `text`.
pub fn ok(text: &str) -> String {
    format!("{} {text}", green("✓"))
}

/// A difference line, colored by its first character: `+` green, `-` red, `~` yellow.
pub fn diff_line(line: &str) -> String {
    match line.chars().next() {
        Some('+') => green(line),
        Some('-') => paint(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))), line),
        Some('~') => yellow(line),
        _ => line.to_string(),
    }
}

/// The Seal mark: three bars, the middle one broken around a red dot. Terminals only.
pub fn mark(beside: &str) -> Option<String> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    let dot = accent("●");
    Some(format!("{}\n{} {dot} {}  {}\n{}", dim("━━━━━━━━━"), dim("━━━"), dim("━━━"), beside, dim("━━━━━━━━━")))
}

/// `rows` as columns padded to their widest cell (the last column is not padded).
pub fn table(rows: &[Vec<String>]) -> Vec<String> {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> =
        (0..columns).map(|c| rows.iter().filter_map(|r| r.get(c)).map(|s| visible(s)).max().unwrap_or(0)).collect();
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (c, cell) in row.iter().enumerate() {
                line.push_str(cell);
                if c + 1 < row.len() {
                    line.push_str(&" ".repeat(widths[c] - visible(cell) + 2));
                }
            }
            line
        })
        .collect()
}

/// Characters a terminal shows: without escape sequences.
fn visible(s: &str) -> usize {
    let mut n = 0;
    let mut escape = false;
    for c in s.chars() {
        match (escape, c) {
            (false, '\u{1b}') => escape = true,
            (true, 'm') => escape = false,
            (true, _) => {}
            (false, _) => n += 1,
        }
    }
    n
}

/// A spinner on stderr naming what it waits for and for how long; nothing when stderr is not
/// a terminal. Stops when dropped.
pub struct Spinner {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Spinner {
    pub fn start(what: &str) -> Self {
        Self::start_since(what, std::time::Instant::now())
    }

    /// As `start`, counting from `started`.
    pub fn start_since(what: &str, started: std::time::Instant) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self { task: None };
        }
        let what = what.to_string();
        let task = tokio::spawn(async move {
            const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            for frame in FRAMES.iter().cycle() {
                let secs = started.elapsed().as_secs();
                eprint!("\r\x1b[2K{} {what} {}", accent(frame), dim(&format!("({})", crate::watch::span(secs))));
                let _ = std::io::stderr().flush();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        Self { task: Some(task) }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
}

/// Whether prompts can be shown: someone is at stdin and stderr.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// One line from the terminal after `question`.
pub fn ask(question: &str) -> anyhow::Result<String> {
    eprint!("{question}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer)? == 0 {
        anyhow::bail!("cancelled");
    }
    Ok(answer.trim().to_string())
}

/// Yes or no; Enter is no.
pub fn confirm(question: &str) -> anyhow::Result<bool> {
    Ok(matches!(ask(&format!("{question} [y/N] "))?.as_str(), "y" | "Y" | "yes"))
}

/// One of `choices` (name, description), by number or name.
pub fn pick<'a>(title: &str, choices: &[(&'a str, String)]) -> anyhow::Result<&'a str> {
    eprintln!("{title}");
    let rows: Vec<Vec<String>> = choices
        .iter()
        .enumerate()
        .map(|(i, (name, about))| vec![format!("  {}", dim(&format!("{}.", i + 1))), bold(name), dim(about)])
        .collect();
    for line in table(&rows) {
        eprintln!("{line}");
    }
    loop {
        let answer = ask(&format!("Choose 1-{}: ", choices.len()))?;
        if let Ok(n) = answer.parse::<usize>() {
            if (1..=choices.len()).contains(&n) {
                return Ok(choices[n - 1].0);
            }
        }
        if let Some((name, _)) = choices.iter().find(|(name, _)| *name == answer) {
            return Ok(name);
        }
    }
}

/// Opens `url` in the default browser; quietly does nothing when it cannot.
pub fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");
    let _ = command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// `say!(...)`: a message, on stdout unless stdout carries a key or a blob.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {
        if $crate::ui::stdout_reserved() { eprintln!($($arg)*) } else { println!($($arg)*) }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_on_visible_width() {
        let rows =
            vec![vec!["a".into(), "long cell".into(), "x".into()], vec!["\u{1b}[1mbold\u{1b}[0m".into(), "b".into()]];
        assert_eq!(table(&rows), ["a     long cell  x", "\u{1b}[1mbold\u{1b}[0m  b"]);
    }
}
