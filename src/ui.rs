use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::{self, AppConfig, Auth, Profile, Rule};
use crate::engines;
use crate::proxy::{self, Routes, Stats};
use crate::subs;
use crate::tasks::{TaskResult, Tasks};
use crate::tray::{Tray, TrayAction};
use crate::util::{app_log, human, log, new_logs, now_secs, Logs};

/// Result of the periodic end-to-end health probe of a running profile.
struct Health {
    ok: bool,
    latency_ms: u64,
    fails: u32,
}

/// Probe target for a profile: explicit config wins; by default xray/sing-box are
/// probed end-to-end against a public host, awg only handshakes with its local SOCKS
/// server (a cluster tunnel may not carry arbitrary internet traffic).
fn probe_target(p: &Profile) -> Option<String> {
    match &p.probe {
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s.clone()),
        None => {
            if p.kind == "awg" {
                None
            } else {
                Some("www.gstatic.com:443".to_string())
            }
        }
    }
}

/// Tail of a sidecar log file (both naming schemes are checked), for the in-app viewer.
fn read_sidecar_log(id: &str, kind: &str) -> String {
    let dir = engines::profile_dir();
    let mut out = String::new();
    for name in [format!("{}.log", id), format!("{}.{}.log", id, kind)] {
        let p = dir.join(&name);
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        if meta.len() == 0 {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            let tail = if text.len() > 65536 {
                let mut cut = text.len() - 65536;
                while !text.is_char_boundary(cut) {
                    cut += 1;
                }
                &text[cut..]
            } else {
                text.as_str()
            };
            let lines: Vec<&str> = tail.lines().collect();
            let start = lines.len().saturating_sub(200);
            out.push_str(&format!("--- {} ---\n", name));
            out.push_str(&lines[start..].join("\n"));
            out.push('\n');
        }
    }
    if out.is_empty() {
        "(no sidecar log yet)".to_string()
    } else {
        out
    }
}

pub struct App {
    cfg: AppConfig,
    logs: Logs,
    stats: Arc<Stats>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    children: HashMap<String, Child>,
    profile_status: HashMap<String, String>,
    refresh_pending: HashSet<String>,
    restart_at: HashMap<String, Instant>,
    restart_attempts: HashMap<String, u32>,
    health: HashMap<String, Health>,
    probe_pending: HashSet<String>,
    last_probe: Instant,
    last_sub_check: Instant,
    tasks: Tasks,
    tray: Option<Tray>,
    tray_state: Option<(bool, bool)>,
    last_health_check: Instant,
    hidden: bool,
    test_did_hide: bool,
    autostart_login: bool,
    quitting: bool,
    routes: Arc<RwLock<Routes>>,
    running: bool,
    started_at: Option<Instant>,
    listen_edit: String,
    import_path: String,
    import_url: String,
    new_suffix: String,
    new_rule_profile: String,
    confirm_install: Option<String>,
    log_view: Option<String>,
    log_view_text: String,
    log_view_at: Instant,
    status: String,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, listen_override: Option<String>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut cfg = config::load();
        if let Some(addr) = listen_override.and_then(|a| config::parse_listen(&a)) {
            cfg.listen = addr;
        }
        let cfg_listen = cfg.listen.clone();
        app_log(&format!(
            "config: {} profiles, autostart={}, listen={}",
            cfg.profiles.len(),
            cfg.autostart,
            cfg.listen
        ));
        let mut app = Self {
            cfg,
            logs: new_logs(),
            stats: Arc::new(Stats::default()),
            alive: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            children: HashMap::new(),
            profile_status: HashMap::new(),
            refresh_pending: HashSet::new(),
            restart_at: HashMap::new(),
            restart_attempts: HashMap::new(),
            health: HashMap::new(),
            probe_pending: HashSet::new(),
            last_probe: Instant::now(),
            last_sub_check: Instant::now(),
            tasks: Tasks::new(cc.egui_ctx.clone()),
            tray: {
                let t = Tray::new(cc.egui_ctx.clone());
                app_log(if t.is_ok() {
                    "tray: created"
                } else {
                    "tray: unavailable"
                });
                t.ok()
            },
            tray_state: None,
            last_health_check: Instant::now(),
            hidden: false,
            test_did_hide: false,
            autostart_login: autostart_state(),
            quitting: false,
            routes: Arc::new(RwLock::new(Routes::default())),
            running: false,
            started_at: None,
            listen_edit: cfg_listen.clone(),
            import_path: String::new(),
            import_url: String::new(),
            new_suffix: String::new(),
            new_rule_profile: String::new(),
            confirm_install: None,
            log_view: None,
            log_view_text: String::new(),
            log_view_at: Instant::now(),
            status: String::new(),
        };
        // LOAD-BEARING on Windows: a minimized window stops honoring egui's internal
        // repaint timers, so the update loop falls asleep and tray events, health checks
        // and probes are never processed (a single request_repaint() from the tray thread
        // does not wake it either). An external periodic repaint keeps the loop alive.
        {
            let ctx = cc.egui_ctx.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_millis(500));
                ctx.request_repaint();
            });
        }
        if let Ok(v) = std::env::var("KUBEVPN_AUTOSTART") {
            let enable = matches!(v.trim(), "1" | "true" | "on");
            if set_autostart(enable).is_ok() {
                app.autostart_login = enable;
            }
        }
        if let Ok(list) = std::env::var("KUBEVPN_INSTALL_ENGINES") {
            for key in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                app.install_engine(key);
            }
        }
        if let Ok(url) = std::env::var("KUBEVPN_IMPORT_URL") {
            if !url.trim().is_empty() {
                app.import_from_url(&url);
            }
        }
        if app.cfg.autostart {
            app.start();
        }
        app.refresh_due_subscriptions();
        app
    }

    fn next_id(&self) -> String {
        let mut i = self.cfg.profiles.len() + 1;
        loop {
            let id = format!("p{}", i);
            if !self.cfg.profiles.iter().any(|p| p.id == id) {
                return id;
            }
            i += 1;
        }
    }

    fn next_port(&self) -> u16 {
        let mut port = 15001;
        while self.cfg.profiles.iter().any(|p| p.port == port) {
            port += 1;
        }
        port
    }

    fn profile_by_id(&self, id: &str) -> Option<&Profile> {
        self.cfg.profiles.iter().find(|p| p.id == id)
    }

    fn port_of(&self, id: &str) -> Option<u16> {
        self.profile_by_id(id).map(|p| p.port)
    }

    fn add_profile(&mut self, text: String, origin: &str) -> bool {
        self.add_profile_named(text, None, origin)
    }

    fn add_profile_named(&mut self, text: String, name: Option<String>, origin: &str) -> bool {
        if self
            .cfg
            .profiles
            .iter()
            .any(|p| p.text.trim() == text.trim())
        {
            self.status = format!("{}: this config is already present, skipped", origin);
            return false;
        }
        let kind = match config::detect_kind(&text) {
            Some(k) => k.to_string(),
            None => {
                self.status = format!("{}: cannot recognise the config format", origin);
                return false;
            }
        };
        let id = self.next_id();
        let port = self.next_port();
        let display = name.unwrap_or_else(|| format!("profile-{}", id.trim_start_matches('p')));
        self.cfg.profiles.push(Profile {
            id: id.clone(),
            name: display,
            kind,
            text,
            port,
            enabled: true,
            subscription: None,
            probe: None,
        });
        self.status = format!("imported {} as {}", origin, id);
        config::save(&self.cfg);
        if self.running {
            self.spawn_by_id(&id);
        } else {
            self.status = format!("imported {} as {} (press Start to connect)", origin, id);
        }
        true
    }

    fn import_from_url(&mut self, url: &str) {
        let url = url.trim().to_string();
        if url.is_empty() {
            self.status = "url is empty".into();
            return;
        }
        if let Some(existing) = self.cfg.subscriptions.iter().find(|s| s.url == url) {
            let id = existing.id.clone();
            self.refresh_subscription(&id);
            return;
        }
        let mut n = self.cfg.subscriptions.len() + 1;
        let mut id = format!("s{}", n);
        while self.cfg.subscriptions.iter().any(|s| s.id == id) {
            n += 1;
            id = format!("s{}", n);
        }
        let name = url
            .split("//")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .filter(|h| !h.is_empty())
            .map(|h| h.to_string())
            .unwrap_or_else(|| format!("subscription {}", n));
        app_log(&format!("subscription {}: add {}", id, url));
        self.cfg.subscriptions.push(config::Subscription {
            id: id.clone(),
            name,
            url: url.clone(),
            profiles: Vec::new(),
            last_refresh: None,
            last_error: None,
        });
        config::save(&self.cfg);
        self.import_url.clear();
        self.refresh_subscription(&id);
    }

    /// Fetches the subscription in the background; the result is applied in apply_subscription.
    fn refresh_subscription(&mut self, id: &str) {
        let url = match self.cfg.subscriptions.iter().find(|s| s.id == id) {
            Some(s) => s.url.clone(),
            None => return,
        };
        self.refresh_pending.insert(id.to_string());
        self.status = format!("refreshing {}...", id);
        self.tasks.refresh(id.to_string(), url, self.logs.clone());
    }

    /// Auto-refresh subscriptions whose last success is older than the configured interval.
    fn refresh_due_subscriptions(&mut self) {
        let hours = self.cfg.subscription_refresh_hours;
        if hours == 0 {
            return;
        }
        let now = now_secs();
        let due: Vec<String> = self
            .cfg
            .subscriptions
            .iter()
            .filter(|s| {
                !self.refresh_pending.contains(&s.id)
                    && s.last_refresh
                        .is_none_or(|t| now.saturating_sub(t) >= hours * 3600)
            })
            .map(|s| s.id.clone())
            .collect();
        for id in due {
            self.refresh_subscription(&id);
        }
    }

    /// Reconciles a fetched subscription with the stored profiles: new configs are added,
    /// changed ones are updated in place, and profiles that disappeared are removed.
    fn apply_subscription(&mut self, id: &str, items: Vec<subs::Item>) {
        let existing: Vec<String> = self
            .cfg
            .profiles
            .iter()
            .filter(|p| p.subscription.as_deref() == Some(id))
            .map(|p| p.id.clone())
            .collect();
        let mut assigned: Vec<Option<String>> = vec![None; items.len()];
        let mut used: HashSet<String> = HashSet::new();

        // 1) match by name, which subscriptions expose as "remarks"
        for (i, item) in items.iter().enumerate() {
            if let Some(name) = &item.name {
                if let Some(p) = self.cfg.profiles.iter().find(|p| {
                    p.name == *name
                        && (p.subscription.as_deref() == Some(id) || p.subscription.is_none())
                        && !used.contains(&p.id)
                }) {
                    assigned[i] = Some(p.id.clone());
                    used.insert(p.id.clone());
                }
            }
        }
        // 2) adopt a standalone profile that carries exactly the same config text
        for (i, item) in items.iter().enumerate() {
            if assigned[i].is_some() {
                continue;
            }
            if let Some(p) = self
                .cfg
                .profiles
                .iter()
                .find(|p| p.text.trim() == item.text.trim() && !used.contains(&p.id))
            {
                assigned[i] = Some(p.id.clone());
                used.insert(p.id.clone());
            }
        }
        // 3) fall back to the previous position in the list
        for (i, slot) in assigned.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            if let Some(old) = existing.get(i) {
                if !used.contains(old) {
                    *slot = Some(old.clone());
                    used.insert(old.clone());
                }
            }
        }

        let mut added = 0;
        let mut updated = 0;
        let mut fresh: Vec<String> = Vec::new();
        for (i, item) in items.into_iter().enumerate() {
            let kind = config::detect_kind(&item.text)
                .unwrap_or("xray")
                .to_string();
            match assigned[i].clone() {
                Some(pid) => {
                    if let Some(p) = self.cfg.profiles.iter_mut().find(|p| p.id == pid) {
                        let same_text = p.text == item.text;
                        if let Some(name) = item.name.clone() {
                            p.name = name;
                        }
                        p.text = item.text;
                        p.kind = kind;
                        p.subscription = Some(id.to_string());
                        if !same_text {
                            updated += 1;
                        }
                    }
                }
                None => {
                    let pid = self.next_id();
                    let port = self.next_port();
                    let name = item
                        .name
                        .unwrap_or_else(|| format!("profile-{}", pid.trim_start_matches('p')));
                    self.cfg.profiles.push(Profile {
                        id: pid.clone(),
                        name,
                        kind,
                        text: item.text,
                        port,
                        enabled: true,
                        subscription: Some(id.to_string()),
                        probe: None,
                    });
                    fresh.push(pid);
                    added += 1;
                }
            }
        }

        let mut keep: HashSet<String> = assigned.into_iter().flatten().collect();
        for pid in &fresh {
            keep.insert(pid.clone());
        }
        let before = self.cfg.profiles.len();
        self.cfg
            .profiles
            .retain(|p| p.subscription.as_deref() != Some(id) || keep.contains(&p.id));
        let removed = before - self.cfg.profiles.len();

        let alive: HashSet<String> = self.cfg.profiles.iter().map(|p| p.id.clone()).collect();
        self.cfg.rules.retain(|r| alive.contains(&r.profile));
        if let Some(dp) = self.cfg.default_profile.clone() {
            if !alive.contains(&dp) {
                self.cfg.default_profile = None;
            }
        }

        let order: Vec<String> = self
            .cfg
            .profiles
            .iter()
            .filter(|p| p.subscription.as_deref() == Some(id))
            .map(|p| p.id.clone())
            .collect();
        if let Some(s) = self.cfg.subscriptions.iter_mut().find(|s| s.id == id) {
            s.profiles = order;
            s.last_refresh = Some(crate::util::now_secs());
            s.last_error = None;
        }
        config::save(&self.cfg);

        for pid in &fresh {
            let enabled = self.profile_by_id(pid).map(|p| p.enabled).unwrap_or(false);
            if self.running && enabled {
                self.spawn_by_id(pid);
            }
        }
        self.refresh_routes();
        self.status = format!(
            "{}: {} new, {} updated, {} removed",
            id, added, updated, removed
        );
    }

    fn remove_subscription(&mut self, id: &str) {
        let ids: Vec<String> = self
            .cfg
            .profiles
            .iter()
            .filter(|p| p.subscription.as_deref() == Some(id))
            .map(|p| p.id.clone())
            .collect();
        for pid in &ids {
            self.stop_by_id(pid);
        }
        self.cfg
            .profiles
            .retain(|p| p.subscription.as_deref() != Some(id));
        self.cfg.rules.retain(|r| !ids.contains(&r.profile));
        if let Some(dp) = self.cfg.default_profile.clone() {
            if ids.contains(&dp) {
                self.cfg.default_profile = None;
            }
        }
        self.cfg.subscriptions.retain(|s| s.id != id);
        self.refresh_pending.remove(id);
        config::save(&self.cfg);
        self.refresh_routes();
        self.status = format!("removed subscription {} and {} profiles", id, ids.len());
    }

    fn import_clipboard(&mut self) {
        match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
            Ok(text) if !text.trim().is_empty() => self.import_payload(text, "clipboard"),
            Ok(_) => self.status = "clipboard is empty".into(),
            Err(e) => self.status = format!("clipboard error: {}", e),
        }
    }

    fn import_file(&mut self, path: &str) {
        match std::fs::read_to_string(path) {
            Ok(text) => self.import_payload(text, path),
            Err(e) => self.status = format!("read {}: {}", path, e),
        }
    }

    /// Accepts a single config, an array of configs, or a list of profiles from a subscription.
    fn import_payload(&mut self, text: String, origin: &str) {
        let t = text.trim().to_string();
        if t.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(&t) {
                Ok(items) => {
                    let total = items.len();
                    let mut added = 0;
                    for item in items {
                        if item.get("outbounds").is_none() {
                            continue;
                        }
                        let name = item
                            .get("remarks")
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string());
                        if self.add_profile_named(item.to_string(), name, origin) {
                            added += 1;
                        }
                    }
                    self.status = format!(
                        "imported {} of {} configs from {} ({} skipped)",
                        added,
                        total,
                        origin,
                        total - added
                    );
                }
                Err(e) => self.status = format!("{}: bad json array: {}", origin, e),
            }
        } else {
            self.add_profile(t, origin);
        }
    }

    fn routes_ui(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(egui::RichText::new("Routes").strong())
            .default_open(true)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "longest suffix / prefix wins; domain, IP or CIDR (10.0.0.0/8)",
                    )
                    .weak()
                    .small(),
                );
                let ids: Vec<(String, String)> = self
                    .cfg
                    .profiles
                    .iter()
                    .map(|p| (p.id.clone(), p.name.clone()))
                    .collect();
                let mut remove_rule: Option<usize> = None;
                let mut move_rule: Option<(usize, i32)> = None;
                egui::Grid::new("rules")
                    .num_columns(5)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("domain / IP / CIDR").strong());
                        ui.label(egui::RichText::new("profile").strong());
                        ui.label("");
                        ui.label("");
                        ui.label("");
                        ui.end_row();
                        for (i, r) in self.cfg.rules.iter().enumerate() {
                            ui.label(&r.suffix);
                            let name = ids
                                .iter()
                                .find(|(id, _)| id == &r.profile)
                                .map(|(_, n)| n.clone())
                                .unwrap_or_else(|| "?".into());
                            ui.label(name);
                            if ui.small_button("x").clicked() {
                                remove_rule = Some(i);
                            }
                            if ui
                                .add_enabled(i > 0, egui::Button::new("▲").small())
                                .clicked()
                            {
                                move_rule = Some((i, -1));
                            }
                            if ui
                                .add_enabled(
                                    i + 1 < self.cfg.rules.len(),
                                    egui::Button::new("▼").small(),
                                )
                                .clicked()
                            {
                                move_rule = Some((i, 1));
                            }
                            ui.end_row();
                        }
                    });
                if let Some(i) = remove_rule {
                    self.cfg.rules.remove(i);
                    config::save(&self.cfg);
                    self.refresh_routes();
                }
                if let Some((i, dir)) = move_rule {
                    let j = (i as i32 + dir) as usize;
                    if j < self.cfg.rules.len() {
                        self.cfg.rules.swap(i, j);
                        config::save(&self.cfg);
                        self.refresh_routes();
                    }
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_suffix)
                            .desired_width(150.0)
                            .hint_text("example.com or 10.0.0.0/8"),
                    );
                    if self.new_rule_profile.is_empty() {
                        if let Some((id, _)) = ids.first() {
                            self.new_rule_profile = id.clone();
                        }
                    }
                    egui::ComboBox::from_id_salt("rule_profile")
                        .selected_text(
                            ids.iter()
                                .find(|(id, _)| id == &self.new_rule_profile)
                                .map(|(_, n)| n.clone())
                                .unwrap_or_else(|| "-".into()),
                        )
                        .show_ui(ui, |ui| {
                            for (id, name) in &ids {
                                ui.selectable_value(
                                    &mut self.new_rule_profile,
                                    id.clone(),
                                    name.as_str(),
                                );
                            }
                        });
                    if ui.button("Add").clicked() {
                        let suffix = self.new_suffix.trim().to_string();
                        if !suffix.is_empty() && !self.new_rule_profile.is_empty() {
                            self.cfg.rules.push(Rule {
                                suffix,
                                profile: self.new_rule_profile.clone(),
                            });
                            self.new_suffix.clear();
                            config::save(&self.cfg);
                            self.refresh_routes();
                        }
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("everything else:");
                    let current = self
                        .cfg
                        .default_profile
                        .as_ref()
                        .and_then(|id| ids.iter().find(|(i, _)| i == id))
                        .map(|(_, n)| n.clone())
                        .unwrap_or_else(|| "direct".into());
                    egui::ComboBox::from_id_salt("default_route")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_label(self.cfg.default_profile.is_none(), "direct")
                                .clicked()
                            {
                                self.cfg.default_profile = None;
                                config::save(&self.cfg);
                                self.refresh_routes();
                            }
                            for (id, name) in &ids {
                                if ui
                                    .selectable_label(
                                        self.cfg.default_profile.as_deref() == Some(id.as_str()),
                                        name.as_str(),
                                    )
                                    .clicked()
                                {
                                    self.cfg.default_profile = Some(id.clone());
                                    config::save(&self.cfg);
                                    self.refresh_routes();
                                }
                            }
                        });
                });
            });
    }

    fn settings_ui(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(egui::RichText::new("Settings").strong())
            .default_open(false)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Engine binaries").strong());
                let (inst, cancel) = engine_row(
                    ui,
                    "awg-wireproxy:",
                    &mut self.cfg.binaries.awg,
                    self.confirm_install.as_deref() == Some("awg"),
                );
                if inst {
                    self.request_install("awg");
                }
                if cancel {
                    self.confirm_install = None;
                }
                let (inst, cancel) = engine_row(
                    ui,
                    "xray:",
                    &mut self.cfg.binaries.xray,
                    self.confirm_install.as_deref() == Some("xray"),
                );
                if inst {
                    self.request_install("xray");
                }
                if cancel {
                    self.confirm_install = None;
                }
                let (inst, cancel) = engine_row(
                    ui,
                    "sing-box:",
                    &mut self.cfg.binaries.singbox,
                    self.confirm_install.as_deref() == Some("singbox"),
                );
                if inst {
                    self.request_install("singbox");
                }
                if cancel {
                    self.confirm_install = None;
                }
                ui.label(
                    egui::RichText::new(
                        "install pulls the latest GitHub release into a per-version folder and verifies its checksum",
                    )
                    .weak()
                    .small(),
                );
                ui.add_space(6.0);
                if ui.button("Save settings").clicked() {
                    config::save(&self.cfg);
                    self.status = "settings saved".into();
                }
                ui.add_space(6.0);
                let mut login = self.autostart_login;
                if ui.checkbox(&mut login, "launch at login").changed() {
                    self.autostart_login = login;
                    match set_autostart(login) {
                        Ok(()) => {
                            self.status = if login {
                                "will start at login".into()
                            } else {
                                "login autostart off".into()
                            }
                        }
                        Err(e) => self.status = format!("autostart: {}", e),
                    }
                }
                if ui
                    .checkbox(&mut self.cfg.minimize_to_tray, "minimize to tray on close")
                    .changed()
                {
                    config::save(&self.cfg);
                }
                if ui
                    .checkbox(
                        &mut self.cfg.fail_closed,
                        "block traffic when the target profile is down",
                    )
                    .changed()
                {
                    config::save(&self.cfg);
                    self.refresh_routes();
                    self.status = if self.cfg.fail_closed {
                        "routes to stopped profiles now block traffic".into()
                    } else {
                        "routes to stopped profiles now fall back to direct".into()
                    };
                }
                if ui
                    .checkbox(&mut self.cfg.log_requests, "log every proxied request")
                    .changed()
                {
                    config::save(&self.cfg);
                    self.refresh_routes();
                }
                ui.horizontal(|ui| {
                    ui.label("auto-refresh subscriptions every");
                    if ui
                        .add(
                            egui::DragValue::new(&mut self.cfg.subscription_refresh_hours)
                                .range(0..=168)
                                .suffix(" h"),
                        )
                        .changed()
                    {
                        config::save(&self.cfg);
                    }
                    ui.label(egui::RichText::new("(0 = off)").weak().small());
                });
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Mixed port authentication").strong());
                let mut enabled = self.cfg.auth.is_some();
                if ui
                    .checkbox(&mut enabled, "require credentials (SOCKS5 user/pass + HTTP Basic)")
                    .changed()
                {
                    self.cfg.auth = if enabled {
                        Some(Auth {
                            user: "kubevpn".to_string(),
                            pass: String::new(),
                        })
                    } else {
                        None
                    };
                    config::save(&self.cfg);
                    self.refresh_routes();
                    self.status = if enabled {
                        "auth enabled: set a password and update every client (kubectl, browsers, DSH)".into()
                    } else {
                        "auth disabled".into()
                    };
                }
                let mut auth_changed = false;
                if let Some(a) = &mut self.cfg.auth {
                    ui.horizontal(|ui| {
                        ui.label("user:");
                        auth_changed |= ui
                            .add(egui::TextEdit::singleline(&mut a.user).desired_width(140.0))
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        ui.label("password:");
                        auth_changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut a.pass)
                                    .password(true)
                                    .desired_width(140.0),
                            )
                            .changed();
                    });
                    if a.pass.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 170, 90),
                            "password is empty - set one before relying on auth",
                        );
                    }
                }
                if auth_changed {
                    config::save(&self.cfg);
                    self.refresh_routes();
                }
            });
    }

    fn set_binary(&mut self, key: &str, path: &str) {
        match key {
            "awg" => self.cfg.binaries.awg = path.to_string(),
            "xray" => self.cfg.binaries.xray = path.to_string(),
            _ => self.cfg.binaries.singbox = path.to_string(),
        }
        config::save(&self.cfg);
    }

    fn install_engine(&mut self, key: &str) {
        self.status = format!("downloading {} in the background...", key);
        self.tasks.install(key.to_string(), self.logs.clone());
    }

    /// Installing over an already configured binary replaces it with the VANILLA
    /// release - a custom build (e.g. Happ's xray with finalmask) would stop being
    /// used. Require an explicit second click before doing that.
    fn request_install(&mut self, key: &str) {
        let current = match key {
            "awg" => self.cfg.binaries.awg.clone(),
            "xray" => self.cfg.binaries.xray.clone(),
            _ => self.cfg.binaries.singbox.clone(),
        };
        if !current.trim().is_empty()
            && std::path::Path::new(&current).exists()
            && self.confirm_install.as_deref() != Some(key)
        {
            self.confirm_install = Some(key.to_string());
            self.status = format!(
                "{} is already configured ({}). Install replaces it with the vanilla release - custom builds will no longer be used. Click install again to confirm.",
                key, current
            );
            return;
        }
        self.confirm_install = None;
        self.install_engine(key);
    }

    fn bin_for(&self, kind: &str) -> String {
        match kind {
            "awg" => self.cfg.binaries.awg.clone(),
            "singbox" => self.cfg.binaries.singbox.clone(),
            _ => self.cfg.binaries.xray.clone(),
        }
    }

    /// Called from the background task result and from the health check.
    fn adopt_child(&mut self, id: &str, child: Child) {
        if self.running {
            self.children.insert(id.to_string(), child);
            self.profile_status.insert(id.to_string(), "up".to_string());
            self.restart_at.remove(id);
            self.refresh_routes();
        } else {
            let mut child = child;
            let _ = child.kill();
        }
    }

    fn build_routes(&self) -> Routes {
        let mut rules = Vec::new();
        for r in &self.cfg.rules {
            let port = if self.children.contains_key(&r.profile) {
                self.port_of(&r.profile)
            } else {
                None
            };
            rules.push((r.suffix.clone(), port));
        }
        let default_configured = self.cfg.default_profile.is_some();
        let default = self
            .cfg
            .default_profile
            .as_deref()
            .filter(|id| self.children.contains_key(*id))
            .and_then(|id| self.port_of(id));
        let auth = self
            .cfg
            .auth
            .as_ref()
            .filter(|a| !a.user.is_empty())
            .map(|a| (a.user.clone(), a.pass.clone()));
        Routes::build(
            rules,
            default,
            default_configured,
            self.cfg.fail_closed,
            auth,
            self.cfg.log_requests,
        )
    }

    fn refresh_routes(&self) {
        if let Ok(mut guard) = self.routes.write() {
            *guard = self.build_routes();
        }
    }

    fn spawn_by_id(&mut self, id: &str) {
        if self.children.contains_key(id) {
            return;
        }
        let profile = match self.profile_by_id(id) {
            Some(p) if p.enabled => p.clone(),
            _ => return,
        };
        let bin = self.bin_for(&profile.kind);
        if bin.trim().is_empty() {
            let msg = format!("no {} binary configured", profile.kind);
            self.profile_status.insert(id.to_string(), msg.clone());
            self.status = msg;
            return;
        }
        if !std::path::Path::new(&bin).exists() {
            let msg = format!("binary not found: {}", bin);
            self.profile_status.insert(id.to_string(), msg.clone());
            self.status = msg;
            return;
        }
        self.profile_status
            .insert(id.to_string(), "starting...".to_string());
        self.tasks
            .spawn_profile(id.to_string(), profile, bin, self.logs.clone());
    }

    fn stop_by_id(&mut self, id: &str) {
        if let Some(mut child) = self.children.remove(id) {
            let _ = child.kill();
            let _ = child.wait();
            log(&self.logs, format!("{} stopped", id));
        }
        self.health.remove(id);
        self.probe_pending.remove(id);
        self.refresh_routes();
    }

    /// Exponential backoff: 5s, 10s, 20s ... capped at 5 min; after 8 consecutive
    /// failures stop trying and surface a crash-loop status instead of spinning forever.
    fn schedule_restart(&mut self, id: &str) {
        let attempts = self.restart_attempts.entry(id.to_string()).or_insert(0);
        if *attempts >= 8 {
            let msg = "crash loop: 8 attempts failed, fix the config and press restart".to_string();
            self.profile_status.insert(id.to_string(), msg.clone());
            log(&self.logs, format!("{}: {}", id, msg));
            self.status = format!("{}: {}", id, msg);
            return;
        }
        let delay = Duration::from_secs((5u64 << (*attempts).min(6)).min(300));
        *attempts += 1;
        self.restart_at
            .insert(id.to_string(), Instant::now() + delay);
        log(
            &self.logs,
            format!(
                "restarting {} in {}s (attempt {})",
                id,
                delay.as_secs(),
                *attempts
            ),
        );
    }

    fn check_children(&mut self) {
        let mut dead: Vec<(String, String)> = Vec::new();
        for (id, child) in self.children.iter_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                dead.push((id.clone(), status.to_string()));
            }
        }
        for (id, status) in dead {
            self.children.remove(&id);
            self.health.remove(&id);
            self.profile_status
                .insert(id.clone(), format!("exited ({})", status));
            log(&self.logs, format!("profile {} exited: {}", id, status));
            if self.running {
                self.schedule_restart(&id);
            }
        }
        if self.running {
            self.refresh_routes();
            let now = Instant::now();
            let due: Vec<String> = self
                .restart_at
                .iter()
                .filter(|(_, t)| **t <= now)
                .map(|(id, _)| id.clone())
                .collect();
            for id in due {
                self.restart_at.remove(&id);
                let enabled = self.profile_by_id(&id).map(|p| p.enabled).unwrap_or(false);
                if enabled {
                    log(&self.logs, format!("restarting {}", id));
                    self.spawn_by_id(&id);
                }
            }
        }
    }

    fn start_probes(&mut self) {
        let targets: Vec<(String, u16, Option<String>)> = self
            .cfg
            .profiles
            .iter()
            .filter(|p| self.children.contains_key(&p.id) && !self.probe_pending.contains(&p.id))
            .map(|p| (p.id.clone(), p.port, probe_target(p)))
            .collect();
        for (id, port, target) in targets {
            self.probe_pending.insert(id.clone());
            self.tasks.probe(id, port, target);
        }
    }

    fn start(&mut self) {
        app_log("start() called");
        engines::kill_stale_sidecars(&self.logs);
        self.stop = Arc::new(AtomicBool::new(false));
        self.alive = Arc::new(AtomicBool::new(true));
        self.health.clear();
        self.probe_pending.clear();
        self.restart_attempts.clear();
        self.restart_at.clear();
        let profiles: Vec<Profile> = self
            .cfg
            .profiles
            .iter()
            .filter(|p| p.enabled)
            .cloned()
            .collect();
        for p in profiles {
            let bin = self.bin_for(&p.kind);
            if bin.trim().is_empty() || !std::path::Path::new(&bin).exists() {
                self.profile_status.insert(
                    p.id.clone(),
                    format!("binary for {} is not configured", p.kind),
                );
                continue;
            }
            self.profile_status
                .insert(p.id.clone(), "starting...".to_string());
            self.tasks
                .spawn_profile(p.id.clone(), p, bin, self.logs.clone());
        }
        self.refresh_routes();
        self.start_listener();
        // First health probe ~5s after start, then every 30s.
        self.last_probe = Instant::now() - Duration::from_secs(25);
    }

    fn start_listener(&mut self) {
        self.stop = Arc::new(AtomicBool::new(false));
        self.alive = Arc::new(AtomicBool::new(true));
        proxy::start(
            self.cfg.listen.clone(),
            self.routes.clone(),
            self.logs.clone(),
            self.stats.clone(),
            self.alive.clone(),
            self.stop.clone(),
        );
        self.running = true;
        self.started_at = Some(Instant::now());
    }

    fn stop_listener(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.alive.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.running = false;
    }

    fn apply_listen(&mut self) {
        match config::parse_listen(&self.listen_edit) {
            Some(addr) => {
                let restart = self.running && addr != self.cfg.listen;
                self.cfg.listen = addr.clone();
                self.listen_edit = addr.clone();
                config::save(&self.cfg);
                if restart {
                    log(&self.logs, format!("moving the listener to {}", addr));
                    self.stop_listener();
                    self.start_listener();
                }
                self.status = format!("listening on {}", addr);
                if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                    if !sa.ip().is_loopback() {
                        self.status = format!(
                            "listening on {} - reachable from the network! Enable auth in Settings",
                            addr
                        );
                    }
                }
            }
            None => {
                self.status = "invalid listen address, expected host:port or a port number".into()
            }
        }
    }

    fn stop(&mut self) {
        self.stop_listener();
        for (id, child) in self.children.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
            log(&self.logs, format!("stopped {}", id));
        }
        self.children.clear();
        self.profile_status.clear();
        self.restart_at.clear();
        self.restart_attempts.clear();
        self.health.clear();
        self.probe_pending.clear();
        engines::clear_pid_file();
        engines::clean_profile_configs();
        self.running = false;
        config::save(&self.cfg);
    }
}

/// One engine row in Settings; returns (install clicked, cancel clicked).
/// A free function so the path borrow and the app borrow do not overlap.
fn engine_row(
    ui: &mut egui::Ui,
    label: &str,
    path: &mut String,
    confirm_armed: bool,
) -> (bool, bool) {
    let mut install = false;
    let mut cancel = false;
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(path).desired_width(220.0));
        if ui.small_button("install").clicked() {
            install = true;
        }
    });
    if confirm_armed {
        ui.colored_label(
            egui::Color32::from_rgb(230, 170, 90),
            "will replace the configured binary with the vanilla release - click install again to confirm",
        );
        if ui.small_button("cancel").clicked() {
            cancel = true;
        }
    }
    (install, cancel)
}

/// Hide/show the window through the platform API.
///
/// egui's ViewportCommand::Visible(false) stops the redraw loop on Windows, so the app would never
/// process the tray menu again. Win32 ShowWindow keeps the loop running while the window is hidden.
#[cfg(windows)]
mod window_ctl {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, GetWindowLongPtrW, SetForegroundWindow, SetWindowLongPtrW, ShowWindow,
        GWL_EXSTYLE, SW_MINIMIZE, SW_RESTORE, SW_SHOW,
    };

    const WS_EX_TOOLWINDOW: isize = 0x0000_0080;
    const WS_EX_APPWINDOW: isize = 0x0004_0000;

    fn find(title: &str) -> Option<*mut std::ffi::c_void> {
        let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { FindWindowW(std::ptr::null(), wide.as_ptr()) };
        if handle.is_null() {
            None
        } else {
            Some(handle)
        }
    }

    /// Minimize and drop the taskbar button. The window keeps its event loop, so the tray stays
    /// responsive; hiding it outright would stop redraws and freeze the UI.
    pub fn hide(title: &str) {
        if let Some(h) = find(title) {
            unsafe {
                let ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
                SetWindowLongPtrW(h, GWL_EXSTYLE, (ex | WS_EX_TOOLWINDOW) & !WS_EX_APPWINDOW);
                ShowWindow(h, SW_MINIMIZE);
            }
        }
    }

    pub fn show(title: &str) {
        if let Some(h) = find(title) {
            unsafe {
                let ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
                SetWindowLongPtrW(h, GWL_EXSTYLE, ex & !WS_EX_TOOLWINDOW);
                ShowWindow(h, SW_SHOW);
                ShowWindow(h, SW_RESTORE);
                SetForegroundWindow(h);
            }
        }
    }
}

#[cfg(not(windows))]
mod window_ctl {
    pub fn hide(_title: &str) {}
    pub fn show(_title: &str) {}
}

fn autostart_builder() -> Option<auto_launch::AutoLaunch> {
    let exe = std::env::current_exe().ok()?.to_string_lossy().to_string();
    auto_launch::AutoLaunchBuilder::new()
        .set_app_name("kubevpn")
        .set_app_path(&exe)
        .build()
        .ok()
}

fn autostart_state() -> bool {
    autostart_builder()
        .and_then(|a| a.is_enabled().ok())
        .unwrap_or(false)
}

fn set_autostart(enable: bool) -> Result<()> {
    let app =
        autostart_builder().ok_or_else(|| anyhow::anyhow!("cannot resolve the executable path"))?;
    if enable {
        app.enable()?;
    } else {
        app.disable()?;
    }
    Ok(())
}

impl Drop for App {
    fn drop(&mut self) {
        for child in self.children.values_mut() {
            let _ = child.kill();
        }
        engines::clean_profile_configs();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.running && !self.alive.load(Ordering::SeqCst) {
            self.running = false;
        }
        // Slow tick for timers (health checks, probes, subscription refresh, uptime).
        // Everything event-driven additionally wakes the loop via request_repaint().
        ctx.request_repaint_after(Duration::from_secs(1));

        while let Some(res) = self.tasks.try_recv() {
            match res {
                TaskResult::Spawned { id, result } => match result {
                    Ok(child) => self.adopt_child(&id, child),
                    Err(e) => {
                        self.profile_status.insert(id.clone(), e.clone());
                        log(&self.logs, format!("profile {} failed: {}", id, e));
                        if self.running {
                            self.schedule_restart(&id);
                        }
                    }
                },
                TaskResult::Refreshed { id, result } => {
                    self.refresh_pending.remove(&id);
                    match result {
                        Ok(items) => {
                            let n = items.len();
                            app_log(&format!("subscription {}: {} configs", id, n));
                            self.apply_subscription(&id, items);
                        }
                        Err(e) => {
                            log(&self.logs, format!("subscription {} failed: {}", id, e));
                            if let Some(s) = self.cfg.subscriptions.iter_mut().find(|s| s.id == id)
                            {
                                s.last_error = Some(e.clone());
                            }
                            config::save(&self.cfg);
                            self.status = format!("{}: {}", id, e);
                        }
                    }
                }
                TaskResult::Installed { key, result } => match result {
                    Ok(path) => {
                        let p = path.to_string_lossy().to_string();
                        self.set_binary(&key, &p);
                        self.status = format!("{} installed: {}", key, p);
                    }
                    Err(e) => {
                        log(&self.logs, format!("install {} failed: {}", key, e));
                        self.status = format!("install {} failed: {}", key, e);
                    }
                },
                TaskResult::Probed { id, result } => {
                    self.probe_pending.remove(&id);
                    if self.children.contains_key(&id) {
                        match result {
                            Ok(ms) => {
                                self.health.insert(
                                    id.clone(),
                                    Health {
                                        ok: true,
                                        latency_ms: ms,
                                        fails: 0,
                                    },
                                );
                                // A healthy tunnel resets the crash-loop counter.
                                self.restart_attempts.remove(&id);
                            }
                            Err(e) => {
                                let fails = self.health.get(&id).map(|h| h.fails).unwrap_or(0) + 1;
                                self.health.insert(
                                    id.clone(),
                                    Health {
                                        ok: false,
                                        latency_ms: 0,
                                        fails,
                                    },
                                );
                                log(
                                    &self.logs,
                                    format!("probe {} failed ({}): {}", id, fails, e),
                                );
                                if fails >= 3 && self.running {
                                    log(
                                        &self.logs,
                                        format!(
                                            "{}: 3 consecutive probe failures, restarting the sidecar",
                                            id
                                        ),
                                    );
                                    self.stop_by_id(&id);
                                    self.schedule_restart(&id);
                                }
                            }
                        }
                    }
                }
            }
        }

        let actions = self.tray.as_ref().map(|t| t.poll()).unwrap_or_default();
        for action in actions {
            match action {
                TrayAction::Show => {
                    app_log("tray: show window");
                    self.hidden = false;
                    window_ctl::show("kubevpn");
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayAction::Start => {
                    if !self.running {
                        self.start();
                    }
                }
                TrayAction::Stop => self.stop(),
                TrayAction::Quit => {
                    self.quitting = true;
                    self.stop();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        if self.cfg.minimize_to_tray
            && !self.quitting
            && !self.hidden
            && ctx.input(|i| i.viewport().close_requested())
        {
            self.hidden = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            window_ctl::hide("kubevpn");
            app_log("window hidden to tray");
            ctx.request_repaint();
        }

        // Diagnostic switch: hide the window at 6s and show it again at 12s,
        // so the hide/show path can be verified without clicking the tray.
        if std::env::var("KUBEVPN_TEST_TRAY").is_ok() {
            let elapsed = self.started_at.map(|t| t.elapsed()).unwrap_or_default();
            if !self.test_did_hide && elapsed > Duration::from_secs(6) {
                self.test_did_hide = true;
                self.hidden = true;
                window_ctl::hide("kubevpn");
                app_log("selftest: window hidden");
            } else if self.test_did_hide && self.hidden && elapsed > Duration::from_secs(12) {
                self.hidden = false;
                window_ctl::show("kubevpn");
                app_log("selftest: window shown");
            }
        }

        if self.last_health_check.elapsed() > Duration::from_secs(2) {
            self.last_health_check = Instant::now();
            self.check_children();
        }

        if self.running && self.last_probe.elapsed() > Duration::from_secs(30) {
            self.last_probe = Instant::now();
            self.start_probes();
        }

        if self.last_sub_check.elapsed() > Duration::from_secs(60) {
            self.last_sub_check = Instant::now();
            self.refresh_due_subscriptions();
        }

        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let files: Vec<PathBuf> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            for f in files {
                self.import_file(&f.to_string_lossy());
            }
        }

        let mut warnings: Vec<String> = Vec::new();
        let fallback = if self.cfg.fail_closed {
            "traffic is blocked"
        } else {
            "traffic goes direct"
        };
        if self.running {
            for r in &self.cfg.rules {
                if !self.children.contains_key(&r.profile) {
                    let name = self
                        .profile_by_id(&r.profile)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| r.profile.clone());
                    warnings.push(format!(
                        ".{} -> {} is not running: {}",
                        r.suffix, name, fallback
                    ));
                }
            }
            if let Some(dp) = self.cfg.default_profile.clone() {
                if !self.children.contains_key(&dp) {
                    let name = self
                        .profile_by_id(&dp)
                        .map(|p| p.name.clone())
                        .unwrap_or(dp.clone());
                    warnings.push(format!(
                        "default route -> {} is not running: {}",
                        name, fallback
                    ));
                }
            }
            if let Ok(sa) = self.cfg.listen.parse::<std::net::SocketAddr>() {
                if !sa.ip().is_loopback() {
                    warnings.push(format!(
                        "listening on {} is reachable from the network{}",
                        self.cfg.listen,
                        if self.cfg.auth.is_some() {
                            ""
                        } else {
                            " WITHOUT authentication - enable auth in Settings"
                        }
                    ));
                }
            }
        }

        // Tray icon reflects the state: gray stopped, green healthy, red degraded.
        let degraded = self.running
            && (self
                .cfg
                .rules
                .iter()
                .any(|r| !self.children.contains_key(&r.profile))
                || self
                    .cfg
                    .default_profile
                    .as_ref()
                    .is_some_and(|d| !self.children.contains_key(d))
                || self.health.values().any(|h| !h.ok));
        let state = (self.running, degraded);
        if self.tray_state != Some(state) {
            self.tray_state = Some(state);
            if let Some(t) = &self.tray {
                let color = if !self.running {
                    [120, 120, 120]
                } else if degraded {
                    [220, 90, 70]
                } else {
                    [70, 180, 120]
                };
                let tooltip = format!(
                    "kubevpn - {}\nconns {}  active {}  up {}  down {}",
                    if self.running { "listening" } else { "stopped" },
                    self.stats.conns.load(Ordering::Relaxed),
                    self.stats.active.load(Ordering::Relaxed),
                    human(self.stats.in_bytes.load(Ordering::Relaxed)),
                    human(self.stats.out_bytes.load(Ordering::Relaxed)),
                );
                t.set_state(color, &tooltip);
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("kubevpn");
                ui.label("one mixed port, user-defined routes");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.running {
                        if ui.button("Stop").clicked() {
                            self.stop();
                        }
                    } else if ui.button("Start").clicked() {
                        self.start();
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.colored_label(
                    if self.running {
                        egui::Color32::from_rgb(120, 220, 120)
                    } else {
                        egui::Color32::GRAY
                    },
                    format!(
                        "{}  {}",
                        if self.running { "listening" } else { "stopped" },
                        self.cfg.listen
                    ),
                );
                if self.running {
                    if let Some(t) = self.started_at {
                        ui.label(format!("uptime {}s", t.elapsed().as_secs()));
                    }
                }
                ui.separator();
                ui.label(format!(
                    "conns {}  active {}  up {}  down {}",
                    self.stats.conns.load(Ordering::Relaxed),
                    self.stats.active.load(Ordering::Relaxed),
                    human(self.stats.in_bytes.load(Ordering::Relaxed)),
                    human(self.stats.out_bytes.load(Ordering::Relaxed))
                ));
            });
            ui.horizontal(|ui| {
                ui.label("listen:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.listen_edit)
                        .desired_width(160.0)
                        .hint_text("127.0.0.1:3080"),
                );
                if ui.button("Apply").clicked() {
                    self.apply_listen();
                }
                ui.label(
                    egui::RichText::new("host:port, or just a port number")
                        .weak()
                        .small(),
                );
            });
            if !self.status.is_empty() {
                ui.label(egui::RichText::new(&self.status).weak().italics());
            }
            for w in &warnings {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 180, 90),
                    format!("warning: {}", w),
                );
            }
            ui.add_space(6.0);
        });

        egui::SidePanel::left("left")
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(8.0);
                        ui.heading("Tunnels");
                        ui.label(
                            egui::RichText::new(
                                "import a config, drop a file, or subscribe to a URL",
                            )
                            .weak()
                            .small(),
                        );
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("From clipboard").clicked() {
                                self.import_clipboard();
                            }
                            ui.add(
                                egui::TextEdit::singleline(&mut self.import_path)
                                    .desired_width(170.0)
                                    .hint_text("file path"),
                            );
                            if ui.button("File").clicked() {
                                let p = self.import_path.clone();
                                self.import_file(&p);
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.import_url)
                                    .desired_width(290.0)
                                    .hint_text("https://sub.example/sub"),
                            );
                            if ui.button("Subscribe").clicked() {
                                let u = self.import_url.clone();
                                self.import_from_url(&u);
                            }
                        });

                        if !self.cfg.subscriptions.is_empty() {
                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Subscriptions").strong());
                            ui.add_space(6.0);
                            let pending = self.refresh_pending.clone();
                            let mut refresh: Option<String> = None;
                            let mut drop_sub: Option<String> = None;
                            for s in &self.cfg.subscriptions {
                                egui::Frame::group(ui.style())
                                    .inner_margin(egui::Margin::same(8.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&s.name).strong());
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{} configs",
                                                    s.profiles.len()
                                                ))
                                                .weak()
                                                .small(),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if ui.small_button("x").clicked() {
                                                        drop_sub = Some(s.id.clone());
                                                    }
                                                    let busy = pending.contains(&s.id);
                                                    let label = if busy {
                                                        "refreshing..."
                                                    } else {
                                                        "refresh"
                                                    };
                                                    if ui
                                                        .add_enabled(
                                                            !busy,
                                                            egui::Button::new(label).small(),
                                                        )
                                                        .clicked()
                                                    {
                                                        refresh = Some(s.id.clone());
                                                    }
                                                },
                                            );
                                        });
                                        ui.label(egui::RichText::new(&s.url).weak().small());
                                        ui.horizontal(|ui| {
                                            if let Some(t) = s.last_refresh {
                                                ui.label(
                                                    egui::RichText::new(format!(
                                                        "updated {}",
                                                        crate::util::ago(t)
                                                    ))
                                                    .weak()
                                                    .small(),
                                                );
                                            }
                                            if let Some(e) = &s.last_error {
                                                let short: String = e.chars().take(80).collect();
                                                ui.label(
                                                    egui::RichText::new(short).small().color(
                                                        egui::Color32::from_rgb(230, 120, 120),
                                                    ),
                                                );
                                            }
                                        });
                                    });
                                ui.add_space(4.0);
                            }
                            if let Some(id) = refresh {
                                self.refresh_subscription(&id);
                            }
                            if let Some(id) = drop_sub {
                                self.remove_subscription(&id);
                            }
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Profiles").strong());
                        ui.add_space(6.0);

                        let mut groups: Vec<(Option<String>, Vec<usize>)> = Vec::new();
                        for (i, p) in self.cfg.profiles.iter().enumerate() {
                            match groups.iter_mut().find(|(k, _)| *k == p.subscription) {
                                Some((_, v)) => v.push(i),
                                None => groups.push((p.subscription.clone(), vec![i])),
                            }
                        }
                        groups.sort_by_key(|(k, _)| if k.is_none() { 0 } else { 1 });

                        let mut remove: Option<String> = None;
                        let mut restart: Option<String> = None;
                        let mut toggle: Option<(String, bool)> = None;
                        let mut test: Option<String> = None;
                        let mut view_log: Option<String> = None;

                        for (key, idxs) in groups {
                            let header = match &key {
                                Some(sid) => self
                                    .cfg
                                    .subscriptions
                                    .iter()
                                    .find(|s| &s.id == sid)
                                    .map(|s| s.name.clone())
                                    .unwrap_or_else(|| sid.clone()),
                                None => "standalone".to_string(),
                            };
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(format!("{} ({})", header, idxs.len()))
                                    .italics()
                                    .weak()
                                    .small(),
                            );
                            for idx in idxs {
                                let (id, name, kind, port) = {
                                    let prof = &self.cfg.profiles[idx];
                                    (
                                        prof.id.clone(),
                                        prof.name.clone(),
                                        prof.kind.clone(),
                                        prof.port,
                                    )
                                };
                                let mut on = self.cfg.profiles[idx].enabled;
                                let running = self.children.contains_key(&id);
                                let health = self.health.get(&id).map(|h| (h.ok, h.latency_ms));
                                let pstats = if running {
                                    Some(self.stats.port_snapshot(port))
                                } else {
                                    None
                                };
                                ui.horizontal(|ui| {
                                    if ui.checkbox(&mut on, "").changed() {
                                        toggle = Some((id.clone(), on));
                                    }
                                    let color = if running {
                                        egui::Color32::from_rgb(120, 220, 120)
                                    } else {
                                        egui::Color32::GRAY
                                    };
                                    ui.colored_label(
                                        color,
                                        egui::RichText::new(if running { "on " } else { "off" })
                                            .monospace(),
                                    );
                                    ui.label(&name);
                                    ui.label(
                                        egui::RichText::new(format!("{} :{}", kind, port))
                                            .weak()
                                            .small(),
                                    );
                                    if let Some((ok, ms)) = health {
                                        if ok {
                                            ui.label(
                                                egui::RichText::new(format!("{} ms", ms))
                                                    .weak()
                                                    .small(),
                                            );
                                        } else {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(230, 120, 120),
                                                egui::RichText::new("probe failed").small(),
                                            );
                                        }
                                    }
                                    if let Some(ps) = pstats {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "↑{} ↓{}",
                                                human(ps.in_bytes),
                                                human(ps.out_bytes)
                                            ))
                                            .weak()
                                            .small(),
                                        );
                                    }
                                    if !running {
                                        if let Some(st) = self.profile_status.get(&id) {
                                            let short: String = st.chars().take(50).collect();
                                            ui.label(
                                                egui::RichText::new(short)
                                                    .small()
                                                    .color(egui::Color32::from_rgb(230, 170, 90)),
                                            );
                                        }
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("x").clicked() {
                                                remove = Some(id.clone());
                                            }
                                            if ui.small_button("restart").clicked() {
                                                restart = Some(id.clone());
                                            }
                                            if ui.small_button("log").clicked() {
                                                view_log = Some(id.clone());
                                            }
                                            if running && ui.small_button("test").clicked() {
                                                test = Some(id.clone());
                                            }
                                        },
                                    );
                                });
                            }
                        }

                        if let Some(id) = restart {
                            if self.running {
                                self.restart_attempts.remove(&id);
                                self.stop_by_id(&id);
                                self.spawn_by_id(&id);
                            } else {
                                self.status = "press Start first".into();
                            }
                        }
                        if let Some((id, enabled)) = toggle {
                            if let Some(p) = self.cfg.profiles.iter_mut().find(|p| p.id == id) {
                                p.enabled = enabled;
                            }
                            config::save(&self.cfg);
                            if self.running {
                                if enabled {
                                    self.spawn_by_id(&id);
                                } else {
                                    self.stop_by_id(&id);
                                }
                            }
                        }
                        if let Some(id) = test {
                            if self.running
                                && self.children.contains_key(&id)
                                && !self.probe_pending.contains(&id)
                            {
                                let target =
                                    self.profile_by_id(&id).map(|p| (p.port, probe_target(p)));
                                if let Some((port, target)) = target {
                                    self.probe_pending.insert(id.clone());
                                    self.tasks.probe(id, port, target);
                                    self.status = "probing...".into();
                                }
                            } else {
                                self.status =
                                    "profile is not running or a probe is in flight".into();
                            }
                        }
                        if let Some(id) = view_log {
                            let kind = self
                                .profile_by_id(&id)
                                .map(|p| p.kind.clone())
                                .unwrap_or_default();
                            self.log_view_text = read_sidecar_log(&id, &kind);
                            self.log_view_at = Instant::now();
                            self.log_view = Some(id);
                        }
                        if let Some(id) = remove {
                            self.stop_by_id(&id);
                            self.cfg.profiles.retain(|p| p.id != id);
                            self.cfg.rules.retain(|r| r.profile != id);
                            for s in &mut self.cfg.subscriptions {
                                s.profiles.retain(|pid| pid != &id);
                            }
                            if self.cfg.default_profile.as_deref() == Some(id.as_str()) {
                                self.cfg.default_profile = None;
                            }
                            self.restart_at.remove(&id);
                            self.restart_attempts.remove(&id);
                            config::save(&self.cfg);
                            self.refresh_routes();
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(4.0);
                        self.routes_ui(ui);
                        ui.add_space(8.0);
                        self.settings_ui(ui);
                        ui.add_space(12.0);
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            if let Some(id) = self.log_view.clone() {
                ui.horizontal(|ui| {
                    ui.heading(format!("Sidecar log: {}", id));
                    if ui.button("back to app log").clicked() {
                        self.log_view = None;
                    }
                });
                ui.add_space(4.0);
                if self.log_view_at.elapsed() > Duration::from_secs(1) {
                    self.log_view_at = Instant::now();
                    let kind = self
                        .profile_by_id(&id)
                        .map(|p| p.kind.clone())
                        .unwrap_or_default();
                    self.log_view_text = read_sidecar_log(&id, &kind);
                }
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(&self.log_view_text)
                                .monospace()
                                .size(12.0),
                        );
                    });
            } else {
                ui.heading("Log");
                ui.add_space(4.0);
                let logs = self.logs.lock().map(|l| l.clone()).unwrap_or_default();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in logs.iter() {
                            ui.label(egui::RichText::new(line).monospace().size(12.0));
                        }
                    });
            }
        });
    }
}
