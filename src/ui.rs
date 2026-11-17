use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use crate::config::{self, AppConfig, Profile, Rule};
use crate::engines;
use crate::proxy::{self, Routes, Stats};
use crate::util::{app_log, human, log, new_logs, Logs};

pub struct App {
    cfg: AppConfig,
    logs: Logs,
    stats: Arc<Stats>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    children: HashMap<String, Child>,
    routes: Arc<RwLock<Routes>>,
    running: bool,
    started_at: Option<Instant>,
    listen_edit: String,
    import_path: String,
    import_url: String,
    new_suffix: String,
    new_rule_profile: String,
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
            routes: Arc::new(RwLock::new(Routes::default())),
            running: false,
            started_at: None,
            listen_edit: cfg_listen.clone(),
            import_path: String::new(),
            import_url: String::new(),
            new_suffix: String::new(),
            new_rule_profile: String::new(),
            status: String::new(),
        };
        if let Ok(url) = std::env::var("KUBEVPN_IMPORT_URL") {
            if !url.trim().is_empty() {
                app.import_from_url(&url);
            }
        }
        if app.cfg.autostart {
            app.start();
        }
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

    fn add_profile(&mut self, text: String, origin: &str) {
        self.add_profile_named(text, None, origin);
    }

    fn add_profile_named(&mut self, text: String, name: Option<String>, origin: &str) {
        let kind = match config::detect_kind(&text) {
            Some(k) => k.to_string(),
            None => {
                self.status = format!("{}: cannot recognise the config format", origin);
                return;
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
        });
        self.status = format!("imported {} as {}", origin, id);
        config::save(&self.cfg);
        if self.running {
            self.spawn_by_id(&id);
        } else {
            self.status = format!("imported {} as {} (press Start to connect)", origin, id);
        }
    }

    fn fetch_url(&self, url: &str) -> Result<String> {
        let mut cmd = Command::new("curl");
        cmd.args(["-sS", "-L", "--max-time", "30", "-A", "v2rayNG/1.9.16", url]);
        cmd.stdin(Stdio::null());
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000);
        let out = cmd.output()?;
        if !out.status.success() {
            bail!("fetch failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    fn import_from_url(&mut self, url: &str) {
        if url.trim().is_empty() {
            self.status = "url is empty".into();
            return;
        }
        app_log(&format!("import url: {}", url.trim()));
        match self.fetch_url(url.trim()) {
            Ok(body) => {
                app_log(&format!("import url: fetched {} bytes", body.len()));
                self.import_payload(body, "subscription");
                app_log(&format!("import url: {}", self.status));
            }
            Err(e) => {
                app_log(&format!("import url failed: {}", e));
                self.status = e.to_string();
            }
        }
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
                        let name = item.get("remarks").and_then(|r| r.as_str()).map(|s| s.to_string());
                        self.add_profile_named(item.to_string(), name, origin);
                        added += 1;
                    }
                    self.status = format!("imported {} of {} configs from {}", added, total, origin);
                }
                Err(e) => self.status = format!("{}: bad json array: {}", origin, e),
            }
        } else {
            self.add_profile(t, origin);
        }
    }

    fn bin_for(&self, kind: &str) -> String {
        match kind {
            "awg" => self.cfg.binaries.awg.clone(),
            "singbox" => self.cfg.binaries.singbox.clone(),
            _ => self.cfg.binaries.xray.clone(),
        }
    }

    fn spawn_profile(&mut self, p: &Profile) -> Result<()> {
        let bin = self.bin_for(&p.kind);
        app_log(&format!("spawning {} ({})", p.name, p.kind));
        let child = engines::spawn(p, &bin, &self.logs)?;
        self.children.insert(p.id.clone(), child);
        Ok(())
    }

    fn build_routes(&self) -> Routes {
        let mut rules = Vec::new();
        for r in &self.cfg.rules {
            if !self.children.contains_key(&r.profile) {
                continue;
            }
            if let Some(port) = self.port_of(&r.profile) {
                rules.push((r.suffix.clone(), port));
            }
        }
        let default = self
            .cfg
            .default_profile
            .as_deref()
            .filter(|id| self.children.contains_key(*id))
            .and_then(|id| self.port_of(id));
        Routes { rules, default }
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
        match self.spawn_profile(&profile) {
            Ok(()) => self.status = format!("{} started", profile.name),
            Err(e) => {
                log(&self.logs, format!("{} failed: {}", profile.name, e));
                self.status = format!("{} failed: {}", profile.name, e);
            }
        }
        self.refresh_routes();
    }

    fn stop_by_id(&mut self, id: &str) {
        if let Some(mut child) = self.children.remove(id) {
            let _ = child.kill();
            let _ = child.wait();
            log(&self.logs, format!("{} stopped", id));
        }
        self.refresh_routes();
    }

    fn start(&mut self) {
        app_log("start() called");
        engines::kill_stale_sidecars(&self.logs);
        self.stop = Arc::new(AtomicBool::new(false));
        self.alive = Arc::new(AtomicBool::new(true));
        let profiles: Vec<Profile> = self.cfg.profiles.iter().filter(|p| p.enabled).cloned().collect();
        for p in &profiles {
            if let Err(e) = self.spawn_profile(p) {
                app_log(&format!("{} failed: {}", p.name, e));
                log(&self.logs, format!("{} failed: {}", p.name, e));
            }
        }
        if self.children.is_empty() {
            self.status = "no tunnels started".into();
        }
        self.refresh_routes();
        self.start_listener();
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
            }
            None => self.status = "invalid listen address, expected host:port or a port number".into(),
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
        engines::clear_pid_file();
        self.running = false;
        config::save(&self.cfg);
    }
}

impl Drop for App {
    fn drop(&mut self) {
        for (_, child) in self.children.iter_mut() {
            let _ = child.kill();
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.running && !self.alive.load(Ordering::SeqCst) {
            self.running = false;
        }
        ctx.request_repaint_after(Duration::from_millis(300));

        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let files: Vec<PathBuf> = ctx
                .input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
            for f in files {
                self.import_file(&f.to_string_lossy());
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
                    format!("{}  {}", if self.running { "listening" } else { "stopped" }, self.cfg.listen),
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
                ui.label(egui::RichText::new("host:port, or just a port number").weak().small());
            });
            if !self.status.is_empty() {
                ui.label(egui::RichText::new(&self.status).weak().italics());
            }
            ui.add_space(6.0);
        });

        egui::SidePanel::left("left").resizable(true).default_width(440.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Profiles");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("From clipboard").clicked() {
                    self.import_clipboard();
                }
                ui.label("or file:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.import_path)
                        .desired_width(140.0)
                        .hint_text("C:\\path\\to\\config"),
                );
                if ui.button("Import").clicked() {
                    let p = self.import_path.clone();
                    self.import_file(&p);
                }
            });
            ui.horizontal(|ui| {
                ui.label("or URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.import_url)
                        .desired_width(220.0)
                        .hint_text("https://sub.example/sub"),
                );
                if ui.button("Import URL").clicked() {
                    let u = self.import_url.clone();
                    self.import_from_url(&u);
                }
            });
            ui.label(egui::RichText::new("you can also drop a file into the window").weak().small());
            ui.add_space(6.0);

            let mut remove: Option<String> = None;
            let mut toggle: Option<(String, bool)> = None;
            for p in self.cfg.profiles.iter_mut() {
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut p.enabled, "").changed() {
                        toggle = Some((p.id.clone(), p.enabled));
                    }
                    let running = self.children.contains_key(&p.id);
                    let color = if running {
                        egui::Color32::from_rgb(120, 220, 120)
                    } else {
                        egui::Color32::GRAY
                    };
                    ui.colored_label(color, if running { "on" } else { "off" });
                    ui.label(&p.name);
                    ui.label(egui::RichText::new(format!("{} :{}", p.kind, p.port)).weak().small());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("x").clicked() {
                            remove = Some(p.id.clone());
                        }
                    });
                });
            }
            if let Some((id, enabled)) = toggle {
                config::save(&self.cfg);
                if self.running {
                    if enabled {
                        self.spawn_by_id(&id);
                    } else {
                        self.stop_by_id(&id);
                    }
                }
            }
            if let Some(id) = remove {
                self.stop_by_id(&id);
                self.cfg.profiles.retain(|p| p.id != id);
                self.cfg.rules.retain(|r| r.profile != id);
                if self.cfg.default_profile.as_deref() == Some(id.as_str()) {
                    self.cfg.default_profile = None;
                }
                config::save(&self.cfg);
                self.refresh_routes();
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);
            ui.heading("Routes");
            ui.add_space(4.0);
            let ids: Vec<(String, String)> = self.cfg.profiles.iter().map(|p| (p.id.clone(), p.name.clone())).collect();
            let mut remove_rule: Option<usize> = None;
            egui::Grid::new("rules").num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("domain suffix").strong());
                ui.label(egui::RichText::new("profile").strong());
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
                    ui.end_row();
                }
            });
            if let Some(i) = remove_rule {
                self.cfg.rules.remove(i);
                config::save(&self.cfg);
                self.refresh_routes();
            }
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_suffix)
                        .desired_width(150.0)
                        .hint_text("example.com"),
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
                            ui.selectable_value(&mut self.new_rule_profile, id.clone(), name.as_str());
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
                        if ui.selectable_label(self.cfg.default_profile.is_none(), "direct").clicked() {
                            self.cfg.default_profile = None;
                            config::save(&self.cfg);
                            self.refresh_routes();
                        }
                        for (id, name) in &ids {
                            if ui
                                .selectable_label(self.cfg.default_profile.as_deref() == Some(id.as_str()), name.as_str())
                                .clicked()
                            {
                                self.cfg.default_profile = Some(id.clone());
                                config::save(&self.cfg);
                                self.refresh_routes();
                            }
                        }
                    });
            });

            ui.add_space(10.0);
            ui.separator();
            ui.label(egui::RichText::new("Engine binaries").strong());
            ui.horizontal(|ui| {
                ui.label("awg-wireproxy:");
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.awg).desired_width(250.0));
            });
            ui.horizontal(|ui| {
                ui.label("xray:");
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.xray).desired_width(250.0));
            });
            ui.horizontal(|ui| {
                ui.label("sing-box:");
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.singbox).desired_width(250.0));
            });
            if ui.button("Save settings").clicked() {
                config::save(&self.cfg);
                self.status = "settings saved".into();
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Log");
            ui.add_space(4.0);
            let logs = self.logs.lock().map(|l| l.clone()).unwrap_or_default();
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for line in logs.iter() {
                    ui.label(egui::RichText::new(line).monospace().size(12.0));
                }
            });
        });
    }
}
