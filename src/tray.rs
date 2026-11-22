use std::sync::mpsc::{channel, Receiver, Sender};

use anyhow::Result;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// Independent restore path: a global hotkey (Win+Shift+K) serviced by our own
/// message-only window and thread. Tray menu delivery can break after the shell
/// recreates the tray (upstream tray-icon/muda subclassing issue); this path does
/// not depend on the tray, winit or the egui loop being redrawn.
#[cfg(windows)]
pub fn spawn_hotkey_listener(ctx: egui::Context, tx: Sender<TrayAction>) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, MOD_SHIFT, MOD_WIN};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, HWND_MESSAGE, MSG, WM_HOTKEY, WNDCLASSW,
    };
    std::thread::spawn(move || unsafe {
        let class_name: Vec<u16> = "kubevpn_hotkey_class"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let instance = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(DefWindowProcW),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassW(&wc) == 0 {
            crate::util::app_log("hotkey: RegisterClassW failed");
            return;
        }
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            crate::util::app_log("hotkey: CreateWindowExW failed");
            return;
        }
        // Win+Shift+K, id 1
        if RegisterHotKey(hwnd, 1, MOD_WIN | MOD_SHIFT, 0x4B) == 0 {
            crate::util::app_log("hotkey: RegisterHotKey failed");
            return;
        }
        crate::util::app_log("hotkey: Win+Shift+K registered");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if msg.message == WM_HOTKEY && msg.wParam == 1 {
                crate::util::app_log("hotkey: Win+Shift+K pressed");
                let _ = tx.send(TrayAction::Show);
                ctx.request_repaint();
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });
}

#[cfg(not(windows))]
pub fn spawn_hotkey_listener(_ctx: egui::Context, _tx: Sender<TrayAction>) {}

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
        spawn_hotkey_listener(ctx.clone(), tx.clone());

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
                    crate::util::app_log(&format!("tray-delivery: menu event {:?}", event.id));
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
                    crate::util::app_log(&format!("tray-delivery: icon event {:?}", event));
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
