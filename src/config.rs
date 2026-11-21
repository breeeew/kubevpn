use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::util::app_log;

fn default_true() -> bool {
    true
}

fn default_refresh_hours() -> u64 {
    24
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Binaries {
    #[serde(default)]
    pub awg: String,
    #[serde(default)]
    pub xray: String,
    #[serde(default)]
    pub singbox: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    /// "awg", "xray" or "singbox"
    pub kind: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Subscription this profile came from, if any.
    #[serde(default)]
    pub subscription: Option<String>,
    /// End-to-end health probe target "host:port" reached through the tunnel.
    /// None: kind default (xray/singbox probe a public host, awg only handshakes).
    /// Some(""): handshake with the local SOCKS server only.
    #[serde(default)]
    pub probe: Option<String>,
}

/// A remote list of configs that can be refreshed; its profiles live in AppConfig::profiles.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Profile ids that belong to this subscription, in server order.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Unix time of the last successful refresh.
    #[serde(default)]
    pub last_refresh: Option<u64>,
    /// Last error, cleared by a successful refresh.
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Domain suffix ("example.com") or an IP/CIDR ("10.0.0.0/8", "2001:db8::/32").
    pub suffix: String,
    pub profile: String,
}

/// Optional credentials for the mixed port (SOCKS5 user/pass and HTTP Basic proxy auth).
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Auth {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub listen: String,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub binaries: Binaries,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    /// When a rule (or the default route) points at a profile that is not running:
    /// false - fall back to a direct connection, true - refuse the connection.
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    /// Require these credentials on the mixed port; None keeps it open (loopback only!).
    #[serde(default)]
    pub auth: Option<Auth>,
    /// Log every proxied request to the window log and kubevpn-app.log.
    #[serde(default = "default_true")]
    pub log_requests: bool,
    /// Auto-refresh subscriptions every N hours; 0 disables.
    #[serde(default = "default_refresh_hours")]
    pub subscription_refresh_hours: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3080".to_string(),
            autostart: false,
            binaries: Binaries::default(),
            profiles: Vec::new(),
            rules: Vec::new(),
            default_profile: None,
            minimize_to_tray: true,
            fail_closed: false,
            subscriptions: Vec::new(),
            auth: None,
            log_requests: true,
            subscription_refresh_hours: default_refresh_hours(),
        }
    }
}

/// Accepts "127.0.0.1:9090", "0.0.0.0:9090" or a bare port number.
pub fn parse_listen(input: &str) -> Option<String> {
    let t = input.trim();
    if t.is_empty() {
        return None;
    }
    let candidate = if t.chars().all(|c| c.is_ascii_digit()) {
        format!("127.0.0.1:{}", t)
    } else {
        t.to_string()
    };
    candidate
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| a.to_string())
}

/// Per-user configuration directory, per platform conventions.
fn user_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(d) = std::env::var_os("APPDATA") {
            return PathBuf::from(d).join("kubevpn");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("kubevpn");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(d) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(d).join("kubevpn");
        }
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(".config").join("kubevpn");
        }
    }
    PathBuf::from(".")
}

/// Where the config lives, in order of preference:
/// 1. next to the executable (portable install),
/// 2. the per-user profile directory,
/// 3. the working directory (legacy; migrated into the profile directory).
///
/// The working directory must never win over the profile directory: an autostart entry
/// launches the exe with an arbitrary working directory, which used to mean "no config".
pub fn config_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.json");
            if p.exists() {
                return p;
            }
        }
    }
    let dir = user_config_dir();
    let p = dir.join("config.json");
    if p.exists() {
        return p;
    }
    let legacy = PathBuf::from("config.json");
    if legacy.exists() {
        if std::fs::create_dir_all(&dir).is_ok() && std::fs::copy(&legacy, &p).is_ok() {
            return p;
        }
        return legacy;
    }
    let _ = std::fs::create_dir_all(&dir);
    p
}

fn parse_config(text: &str) -> Option<AppConfig> {
    let text = text.trim_start_matches('\u{feff}');
    let mut cfg: AppConfig = serde_json::from_str(text).ok()?;
    // Self-heal profile kinds for configs imported by older versions.
    for p in cfg.profiles.iter_mut() {
        if let Some(kind) = detect_kind(&p.text) {
            if p.kind != kind {
                p.kind = kind.to_string();
            }
        }
    }
    Some(cfg)
}

pub fn load() -> AppConfig {
    let path = config_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return AppConfig::default();
    };
    if let Some(cfg) = parse_config(&text) {
        return cfg;
    }
    // The file exists but is corrupt. Never silently start from scratch: preserve the
    // evidence, then try the previous generation written by save().
    app_log(&format!(
        "config: {} is corrupt, keeping a copy",
        path.display()
    ));
    let _ = std::fs::copy(&path, path.with_extension("json.corrupt"));
    let bak = path.with_extension("json.bak");
    if let Ok(text) = std::fs::read_to_string(&bak) {
        if let Some(cfg) = parse_config(&text) {
            app_log("config: restored from config.json.bak");
            return cfg;
        }
    }
    app_log("config: no usable backup, starting with defaults (corrupt file preserved)");
    AppConfig::default()
}

/// Atomic save: write a temp file, keep the previous generation as .bak, then rename
/// over the target. A crash mid-write can no longer truncate the only copy of the keys.
pub fn save(cfg: &AppConfig) {
    if let Err(e) = try_save(cfg) {
        app_log(&format!("config: save failed: {}", e));
    }
}

fn try_save(cfg: &AppConfig) -> anyhow::Result<()> {
    let path = config_path();
    let text = serde_json::to_string_pretty(cfg)? + "\n";
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let _ = std::fs::copy(&path, path.with_extension("json.bak"));
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    rename_replace(&tmp, &path)?;
    Ok(())
}

#[cfg(windows)]
fn rename_replace(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |p: &std::path::Path| -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let ok = unsafe {
        MoveFileExW(
            wide(from).as_ptr(),
            wide(to).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        anyhow::bail!("MoveFileExW failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_replace(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    std::fs::rename(from, to)?;
    Ok(())
}

/// Guess the engine from the config text.
pub fn detect_kind(text: &str) -> Option<&'static str> {
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(outs) = v.get("outbounds").and_then(|o| o.as_array()) {
                if outs.iter().any(|o| o.get("protocol").is_some()) {
                    return Some("xray");
                }
                if outs.iter().any(|o| o.get("type").is_some()) {
                    return Some("singbox");
                }
            }
            // A subscription payload: an array of complete configs.
            return Some("xray");
        }
    }
    if text.contains("[Interface]") && text.contains("[Peer]") {
        Some("awg")
    } else {
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_amneziawg_ini() {
        let text = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n";
        assert_eq!(detect_kind(text), Some("awg"));
    }

    #[test]
    fn detects_xray_by_protocol() {
        let text = r#"{"outbounds":[{"protocol":"vless","tag":"p"}]}"#;
        assert_eq!(detect_kind(text), Some("xray"));
    }

    #[test]
    fn detects_singbox_by_type() {
        let text = r#"{"outbounds":[{"type":"vless","tag":"p"}]}"#;
        assert_eq!(detect_kind(text), Some("singbox"));
    }

    #[test]
    fn detects_subscription_array() {
        let text = r#"[{"outbounds":[{"protocol":"vless"}]},{"outbounds":[{"protocol":"vmess"}]}]"#;
        assert_eq!(detect_kind(text), Some("xray"));
    }

    #[test]
    fn rejects_unknown_text() {
        assert_eq!(detect_kind("hello"), None);
    }

    #[test]
    fn parses_bare_port() {
        assert_eq!(parse_listen("3999"), Some("127.0.0.1:3999".to_string()));
    }

    #[test]
    fn parses_host_and_port() {
        assert_eq!(
            parse_listen(" 0.0.0.0:9090 "),
            Some("0.0.0.0:9090".to_string())
        );
    }

    #[test]
    fn rejects_garbage_listen() {
        assert_eq!(parse_listen("nope"), None);
        assert_eq!(parse_listen("127.0.0.1:99999"), None);
        assert_eq!(parse_listen(""), None);
    }

    #[test]
    fn defaults_are_backwards_compatible() {
        let cfg: AppConfig = serde_json::from_str(r#"{"listen":"127.0.0.1:3080"}"#).unwrap();
        assert!(cfg.log_requests);
        assert_eq!(cfg.subscription_refresh_hours, 24);
        assert!(cfg.auth.is_none());
        assert!(!cfg.fail_closed);
    }

    #[test]
    fn corrupt_text_is_rejected_not_defaulted_silently() {
        assert!(parse_config("{oops").is_none());
        assert!(parse_config(r#"{"listen":"127.0.0.1:1"}"#).is_some());
    }

    #[test]
    fn bom_is_stripped() {
        let cfg = parse_config("\u{feff}{\"listen\":\"127.0.0.1:1\"}").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:1");
    }
}
