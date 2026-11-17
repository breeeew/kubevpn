use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Logs = Arc<Mutex<VecDeque<String>>>;

pub fn new_logs() -> Logs {
    Arc::new(Mutex::new(VecDeque::new()))
}

pub fn clock() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() % 86400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

pub fn log(logs: &Logs, msg: impl Into<String>) {
    let mut guard = logs.lock().unwrap();
    guard.push_back(format!("[{}] {}", clock(), msg.into()));
    while guard.len() > 400 {
        guard.pop_front();
    }
}

/// Append a line to the diagnostic file: %TEMP%/kubevpn-app.log
pub fn app_log(msg: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("kubevpn-app.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} {}", clock(), msg);
    }
}

/// Honor the usual proxy environment variables for outbound HTTP requests.
pub fn proxy_from_env() -> Option<String> {
    for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Hide the console window of a child process on Windows; no-op elsewhere.
#[cfg(windows)]
pub fn hide_console(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
pub fn hide_console(_cmd: &mut std::process::Command) {}

pub fn human(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "K", "M", "G"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.1}{}", v, UNITS[i])
}

/// Remove ANSI escape sequences coming from child process output.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            while let Some(n) = chars.next() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
