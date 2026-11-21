use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Logs = Arc<Mutex<VecDeque<String>>>;

pub fn new_logs() -> Logs {
    Arc::new(Mutex::new(VecDeque::new()))
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Human readable age of a timestamp: "just now", "5 min ago", "3 h ago", "2 d ago".
pub fn ago(unix_secs: u64) -> String {
    let now = now_secs();
    let diff = now.saturating_sub(unix_secs);
    match diff {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", diff / 60),
        3600..=86399 => format!("{} h ago", diff / 3600),
        _ => format!("{} d ago", diff / 86400),
    }
}

pub fn clock() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

pub fn log(logs: &Logs, msg: impl Into<String>) {
    let mut guard = logs.lock().unwrap();
    guard.push_back(format!("[{}] {}", clock(), msg.into()));
    while guard.len() > 400 {
        guard.pop_front();
    }
}

/// Diagnostic file %TEMP%/kubevpn-app.log, kept open and rotated at 5 MiB
/// (one previous generation is kept as kubevpn-app.log.1).
struct AppLog {
    file: Option<std::fs::File>,
    size: u64,
}

const APP_LOG_MAX: u64 = 5 * 1024 * 1024;

pub fn app_log(msg: &str) {
    use std::io::Write;
    static LOG: OnceLock<Mutex<AppLog>> = OnceLock::new();
    let m = LOG.get_or_init(|| {
        Mutex::new(AppLog {
            file: None,
            size: 0,
        })
    });
    let mut g = match m.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let path = std::env::temp_dir().join("kubevpn-app.log");
    if g.file.is_none() {
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            g.size = f.metadata().map(|m| m.len()).unwrap_or(0);
            g.file = Some(f);
        }
    }
    if g.size > APP_LOG_MAX {
        g.file = None;
        let old = path.with_extension("log.1");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&path, &old);
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            g.file = Some(f);
            g.size = 0;
        }
    }
    if let Some(f) = g.file.as_mut() {
        let line = format!("{} {}\n", clock(), msg);
        if f.write_all(line.as_bytes()).is_ok() {
            g.size += line.len() as u64;
        }
    }
}

/// Honor the usual proxy environment variables for outbound HTTP requests.
pub fn proxy_from_env() -> Option<String> {
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
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
            for n in chars.by_ref() {
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

/// Decode base64 (standard or URL-safe alphabet, padding optional, whitespace ignored).
/// Used for subscription payloads and HTTP Basic proxy credentials.
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in input.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let v: u32 = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Percent-decode a URI component ("a%20b" -> "a b"); '+' is left as-is.
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_standard_and_urlsafe() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(b64_decode("-_8=").unwrap(), &[0xfb, 0xff]);
        assert_eq!(b64_decode("a G V s b G 8=").unwrap(), b"hello");
        assert!(b64_decode("!!!").is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%F0%9F%87%B3%F0%9F%87%B1"), "🇳🇱");
        assert_eq!(percent_decode("plain+text"), "plain+text");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        assert_eq!(percent_decode("truncated%2"), "truncated%2");
    }

    #[test]
    fn human_bytes() {
        assert_eq!(human(0), "0.0B");
        assert_eq!(human(1536), "1.5K");
    }
}
