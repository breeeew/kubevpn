use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    pub suffix: String,
    pub profile: String,
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
    candidate.parse::<std::net::SocketAddr>().ok().map(|a| a.to_string())
}

pub fn config_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.json");
            if p.exists() {
                return p;
            }
        }
    }
    PathBuf::from("config.json")
}

pub fn load() -> AppConfig {
    let path = config_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = text.trim_start_matches('\u{feff}');
        if let Ok(mut cfg) = serde_json::from_str::<AppConfig>(text) {
            // Self-heal profile kinds for configs imported by older versions.
            for p in cfg.profiles.iter_mut() {
                if let Some(kind) = detect_kind(&p.text) {
                    if p.kind != kind {
                        p.kind = kind.to_string();
                    }
                }
            }
            return cfg;
        }
    }
    AppConfig::default()
}

pub fn save(cfg: &AppConfig) {
    if let Ok(text) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(config_path(), text + "\n");
    }
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
