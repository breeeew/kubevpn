use anyhow::Result;
use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub enum TrayAction {
    Show,
    Start,
    Stop,
    Quit,
}

pub struct Tray {
    _icon: TrayIcon,
    show: MenuId,
    start: MenuId,
    stop: MenuId,
    quit: MenuId,
}

fn make_icon() -> Icon {
    // Simple 32x32 rounded square, drawn in code so the repo carries no binary assets.
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let cx = (size as f32 - 1.0) / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cx;
            let inside = (dx * dx + dy * dy).sqrt() < 15.0;
            let i = ((y * size + x) * 4) as usize;
            if inside {
                rgba[i] = 70;
                rgba[i + 1] = 180;
                rgba[i + 2] = 120;
                rgba[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).expect("icon")
}

impl Tray {
    pub fn new() -> Result<Self> {
        let menu = Menu::new();
        let show = MenuItem::new("Show window", true, None);
        let start = MenuItem::new("Start tunnels", true, None);
        let stop = MenuItem::new("Stop tunnels", true, None);
        let quit = MenuItem::new("Quit", true, None);
        menu.append(&show)?;
        menu.append(&start)?;
        menu.append(&stop)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit)?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("kubevpn")
            .with_icon(make_icon())
            .build()?;

        Ok(Self {
            _icon: icon,
            show: show.id().clone(),
            start: start.id().clone(),
            stop: stop.id().clone(),
            quit: quit.id().clone(),
        })
    }

    /// Drain pending tray events.
    pub fn poll(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if event.id == self.show {
                actions.push(TrayAction::Show);
            } else if event.id == self.start {
                actions.push(TrayAction::Start);
            } else if event.id == self.stop {
                actions.push(TrayAction::Stop);
            } else if event.id == self.quit {
                actions.push(TrayAction::Quit);
            }
        }
        if let Ok(event) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if matches!(event, tray_icon::TrayIconEvent::DoubleClick { .. }) {
                actions.push(TrayAction::Show);
            }
        }
        actions
    }
}
