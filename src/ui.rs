use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::{self, AppConfig, Profile, Rule};
use crate::engines;
use crate::proxy::{self, Routes, Stats};
use crate::tasks::{TaskResult, Tasks};
use crate::tray::{Tray, TrayAction};
use crate::util::{app_log, human, log, new_logs, proxy_from_env, Logs};

pub struct App {
    cfg: AppConfig,
    logs: Logs,
    stats: Arc<Stats>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    children: HashMap<String, Child>,
    profile_status: HashMap<String, String>,
    restart_at: HashMap<String, Instant>,
    tasks: Tasks,
    tray: Option<Tray>,
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
            restart_at: HashMap::new(),
            tasks: Tasks::new(),
            tray: {
                let t = Tray::new(cc.egui_ctx.clone());
                app_log(if t.is_ok() { "tray: created" } else { "tray: unavailable" });
                t.ok()
            },
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
            status: String::new(),
        };
        {
            // A hidden window stops receiving redraws, so keep the UI loop alive:
            // without this the tray menu and "show" requests would never be processed.
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
        if self.cfg.profiles.iter().any(|p| p.text.trim() == text.trim()) {
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

    fn fetch_url(&self, url: &str) -> Result<String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .user_agent("v2rayNG/1.9.16");
        if let Some(p) = proxy_from_env() {
            match ureq::Proxy::new(&p) {
                Ok(proxy) => builder = builder.proxy(proxy),
                Err(e) => app_log(&format!("ignoring proxy {}: {}", p, e)),
            }
        }
        let agent = builder.build();
        let body = agent.get(url).call()?.into_string()?;
        Ok(body)
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
                        if self.add_profile_named(item.to_string(), name, origin) {
                            added += 1;
                        }
                    }
                    self.status = format!("imported {} of {} configs from {} ({} skipped)", added, total, origin, total - added);
                }
                Err(e) => self.status = format!("{}: bad json array: {}", origin, e),
            }
        } else {
            self.add_profile(t, origin);
        }
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
        Routes {
            rules,
            default,
            default_configured,
            fail_closed: self.cfg.fail_closed,
        }
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
        self.profile_status.insert(id.to_string(), "starting...".to_string());
        self.tasks
            .spawn_profile(id.to_string(), profile, bin, self.logs.clone());
    }

    fn stop_by_id(&mut self, id: &str) {
        if let Some(mut child) = self.children.remove(id) {
            let _ = child.kill();
            let _ = child.wait();
            log(&self.logs, format!("{} stopped", id));
        }
        self.refresh_routes();
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
            self.profile_status.insert(id.clone(), format!("exited ({})", status));
            log(&self.logs, format!("profile {} exited: {}", id, status));
            if self.running {
                self.restart_at.insert(id, Instant::now() + Duration::from_secs(5));
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

    fn start(&mut self) {
        app_log("start() called");
        engines::kill_stale_sidecars(&self.logs);
        self.stop = Arc::new(AtomicBool::new(false));
        self.alive = Arc::new(AtomicBool::new(true));
        let profiles: Vec<Profile> = self.cfg.profiles.iter().filter(|p| p.enabled).cloned().collect();
        for p in profiles {
            let bin = self.bin_for(&p.kind);
            if bin.trim().is_empty() || !std::path::Path::new(&bin).exists() {
                self.profile_status
                    .insert(p.id.clone(), format!("binary for {} is not configured", p.kind));
                continue;
            }
            self.profile_status.insert(p.id.clone(), "starting...".to_string());
            self.tasks.spawn_profile(p.id.clone(), p, bin, self.logs.clone());
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
        self.profile_status.clear();
        self.restart_at.clear();
        engines::clear_pid_file();
        self.running = false;
        config::save(&self.cfg);
    }
}

/// Hide/show the window through the platform API.
///
/// egui's ViewportCommand::Visible(false) stops the redraw loop on Windows, so the app would never
/// process the tray menu again. Win32 ShowWindow keeps the loop running while the window is hidden.
#[cfg(windows)]
mod window_ctl {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, GetWindowLongPtrW, SetForegroundWindow, SetWindowLongPtrW, ShowWindow, GWL_EXSTYLE,
        SW_MINIMIZE, SW_RESTORE, SW_SHOW,
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
    let app = autostart_builder().ok_or_else(|| anyhow::anyhow!("cannot resolve the executable path"))?;
    if enable {
        app.enable()?;
    } else {
        app.disable()?;
    }
    Ok(())
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

        while let Some(res) = self.tasks.try_recv() {
            match res {
                TaskResult::Spawned { id, result } => match result {
                    Ok(child) => self.adopt_child(&id, child),
                    Err(e) => {
                        self.profile_status.insert(id.clone(), e.clone());
                        log(&self.logs, format!("profile {} failed: {}", id, e));
                    }
                },
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

        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let files: Vec<PathBuf> = ctx
                .input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
            for f in files {
                self.import_file(&f.to_string_lossy());
            }
        }

        let mut warnings: Vec<String> = Vec::new();
        let fallback = if self.cfg.fail_closed { "traffic is blocked" } else { "traffic goes direct" };
        if self.running {
            for r in &self.cfg.rules {
                if !self.children.contains_key(&r.profile) {
                    let name = self
                        .profile_by_id(&r.profile)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| r.profile.clone());
                    warnings.push(format!(".{} -> {} is not running: {}", r.suffix, name, fallback));
                }
            }
            if let Some(dp) = self.cfg.default_profile.clone() {
                if !self.children.contains_key(&dp) {
                    let name = self.profile_by_id(&dp).map(|p| p.name.clone()).unwrap_or(dp.clone());
                    warnings.push(format!("default route -> {} is not running: {}", name, fallback));
                }
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
            for w in &warnings {
                ui.colored_label(egui::Color32::from_rgb(230, 180, 90), format!("warning: {}", w));
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
            let mut restart: Option<String> = None;
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
                    if !running {
                        if let Some(st) = self.profile_status.get(&p.id) {
                            let short: String = st.chars().take(60).collect();
                            ui.label(egui::RichText::new(short).small().color(egui::Color32::from_rgb(230, 170, 90)));
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("x").clicked() {
                            remove = Some(p.id.clone());
                        }
                        if ui.small_button("restart").clicked() {
                            restart = Some(p.id.clone());
                        }
                    });
                });
            }
            if let Some(id) = restart {
                if self.running {
                    self.stop_by_id(&id);
                    self.spawn_by_id(&id);
                } else {
                    self.status = "press Start first".into();
                }
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
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.awg).desired_width(220.0));
                if ui.small_button("install").clicked() {
                    self.install_engine("awg");
                }
            });
            ui.horizontal(|ui| {
                ui.label("xray:");
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.xray).desired_width(220.0));
                if ui.small_button("install").clicked() {
                    self.install_engine("xray");
                }
            });
            ui.horizontal(|ui| {
                ui.label("sing-box:");
                ui.add(egui::TextEdit::singleline(&mut self.cfg.binaries.singbox).desired_width(220.0));
                if ui.small_button("install").clicked() {
                    self.install_engine("singbox");
                }
            });
            ui.label(egui::RichText::new("install pulls the latest GitHub release and verifies its checksum").weak().small());
            if ui.button("Save settings").clicked() {
                config::save(&self.cfg);
                self.status = "settings saved".into();
            }
            ui.add_space(6.0);
            let mut login = self.autostart_login;
            if ui.checkbox(&mut login, "launch at login").changed() {
                self.autostart_login = login;
                match set_autostart(login) {
                    Ok(()) => self.status = if login { "will start at login".into() } else { "login autostart off".into() },
                    Err(e) => self.status = format!("autostart: {}", e),
                }
            }
            if ui.checkbox(&mut self.cfg.minimize_to_tray, "minimize to tray on close").changed() {
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
