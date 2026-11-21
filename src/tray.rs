use std::sync::mpsc::{channel, Receiver, Sender};

use anyhow::Result;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub enum TrayAction {
    Show,
    Start,
    Stop,
    Quit,
}

pub struct Tray {
    icon: TrayIcon,
    rx: Receiver<TrayAction>,
}

fn make_icon(rgb: [u8; 3]) -> Icon {
    // Simple 32x32 circle, drawn in code so the repo carries no binary assets.
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let cx = (size as f32 - 1.0) / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cx;
            if (dx * dx + dy * dy).sqrt() < 15.0 {
                let i = ((y * size + x) * 4) as usize;
                rgba[i] = rgb[0];
                rgba[i + 1] = rgb[1];
                rgba[i + 2] = rgb[2];
                rgba[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).expect("icon")
}

impl Tray {
    /// Menu and icon events are forwarded through a channel; every event also wakes the UI,
    /// because a window hidden to the tray stops receiving redraws on its own.
    pub fn new(ctx: egui::Context) -> Result<Self> {
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
            .with_icon(make_icon([120, 120, 120]))
            .build()?;

        let (tx, rx) = channel::<TrayAction>();

        let show_id = show.id().clone();
        let start_id = start.id().clone();
        let stop_id = stop.id().clone();
        let quit_id = quit.id().clone();
        {
            let tx: Sender<TrayAction> = tx.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let events = tray_icon::menu::MenuEvent::receiver();
                while let Ok(event) = events.recv() {
                    let action = if event.id == show_id {
                        Some(TrayAction::Show)
                    } else if event.id == start_id {
                        Some(TrayAction::Start)
                    } else if event.id == stop_id {
                        Some(TrayAction::Stop)
                    } else if event.id == quit_id {
                        Some(TrayAction::Quit)
                    } else {
                        None
                    };
                    if let Some(action) = action {
                        let _ = tx.send(action);
                        ctx.request_repaint();
                    }
                }
            });
        }
        {
            let tx: Sender<TrayAction> = tx.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let events = tray_icon::TrayIconEvent::receiver();
                while let Ok(event) = events.recv() {
                    match event {
                        tray_icon::TrayIconEvent::DoubleClick { .. }
                        | tray_icon::TrayIconEvent::Click { .. } => {
                            let _ = tx.send(TrayAction::Show);
                            ctx.request_repaint();
                        }
                        _ => {}
                    }
                }
            });
        }

        Ok(Self { icon, rx })
    }

    /// Reflect the app state in the tray: color (gray stopped / green running /
    /// red degraded) and a tooltip with live counters.
    pub fn set_state(&self, rgb: [u8; 3], tooltip: &str) {
        let _ = self.icon.set_icon(Some(make_icon(rgb)));
        let _ = self.icon.set_tooltip(Some(tooltip));
    }

    pub fn poll(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(action) = self.rx.try_recv() {
            actions.push(action);
        }
        actions
    }
}
