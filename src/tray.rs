use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
#[cfg(not(windows))]
use tray_icon::TrayIcon;
use tray_icon::{Icon, TrayIconBuilder};

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
    rx: Receiver<TrayAction>,
    /// Windows: the TrayIcon lives on its own thread with its own message pump, so
    /// the modal TrackPopupMenu loop blocks THAT thread, never the egui UI thread
    /// (a modal menu on the UI thread froze the whole app: heartbeats stopped and
    /// tray/hotkey actions were never polled again).
    #[cfg(windows)]
    state: TrayState,
    #[cfg(windows)]
    tray_tid: u32,
    #[cfg(not(windows))]
    icon: TrayIcon,
}

#[cfg(windows)]
const WM_APP_TRAY_STATE: u32 = 0x8001;

#[cfg(windows)]
type TrayState = Arc<Mutex<Option<([u8; 3], String)>>>;

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
        let (tx, rx) = channel::<TrayAction>();
        spawn_hotkey_listener(ctx.clone(), tx.clone());

        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                DispatchMessageW, GetMessageW, TranslateMessage, MSG, WM_QUIT,
            };
            let state: TrayState = Arc::new(Mutex::new(None));
            let state2 = state.clone();
            let (ready_tx, ready_rx) = channel::<std::result::Result<u32, String>>();
            std::thread::spawn(move || {
                let menu = Menu::new();
                let show = MenuItem::new("Show window", true, None);
                let start = MenuItem::new("Start tunnels", true, None);
                let stop = MenuItem::new("Stop tunnels", true, None);
                let quit = MenuItem::new("Quit", true, None);
                let built = (|| -> Result<()> {
                    menu.append(&show)?;
                    menu.append(&start)?;
                    menu.append(&stop)?;
                    menu.append(&PredefinedMenuItem::separator())?;
                    menu.append(&quit)?;
                    Ok(())
                })();
                if let Err(e) = built {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
                let icon = match TrayIconBuilder::new()
                    .with_menu(Box::new(menu))
                    // Discord/Steam/Telegram convention: left click opens the window,
                    // right click opens the menu.
                    .with_menu_on_left_click(false)
                    .with_tooltip("kubevpn")
                    .with_icon(make_icon([120, 120, 120]))
                    .build()
                {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let tid = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
                let _ = ready_tx.send(Ok(tid));

                let show_id = show.id().clone();
                let start_id = start.id().clone();
                let stop_id = stop.id().clone();
                let quit_id = quit.id().clone();
                {
                    let tx = tx.clone();
                    let ctx = ctx.clone();
                    std::thread::spawn(move || {
                        let events = tray_icon::menu::MenuEvent::receiver();
                        while let Ok(event) = events.recv() {
                            crate::util::app_log(&format!(
                                "tray-delivery: menu event {:?}",
                                event.id
                            ));
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
                    let tx = tx.clone();
                    let ctx = ctx.clone();
                    std::thread::spawn(move || {
                        let events = tray_icon::TrayIconEvent::receiver();
                        while let Ok(event) = events.recv() {
                            match event {
                                tray_icon::TrayIconEvent::DoubleClick {
                                    button: tray_icon::MouseButton::Left,
                                    ..
                                }
                                | tray_icon::TrayIconEvent::Click {
                                    button: tray_icon::MouseButton::Left,
                                    button_state: tray_icon::MouseButtonState::Up,
                                    ..
                                } => {
                                    crate::util::app_log("tray-delivery: left click -> show");
                                    let _ = tx.send(TrayAction::Show);
                                    ctx.request_repaint();
                                }
                                _ => {}
                            }
                        }
                    });
                }

                // Own message pump: the modal menu loop runs here, not on the UI thread.
                unsafe {
                    let mut msg: MSG = std::mem::zeroed();
                    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                        if msg.hwnd.is_null() && msg.message == WM_APP_TRAY_STATE {
                            let pending = state2.lock().unwrap().take();
                            if let Some((rgb, tooltip)) = pending {
                                let _ = icon.set_icon(Some(make_icon(rgb)));
                                let _ = icon.set_tooltip(Some(tooltip));
                            }
                            continue;
                        }
                        if msg.message == WM_QUIT {
                            break;
                        }
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
                drop(icon);
            });
            let tid = ready_rx
                .recv()
                .map_err(|_| anyhow::anyhow!("tray thread died"))?
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(Self {
                rx,
                state,
                tray_tid: tid,
            })
        }

        #[cfg(not(windows))]
        {
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
                .with_menu_on_left_click(false)
                .with_tooltip("kubevpn")
                .with_icon(make_icon([120, 120, 120]))
                .build()?;
            let show_id = show.id().clone();
            let start_id = start.id().clone();
            let stop_id = stop.id().clone();
            let quit_id = quit.id().clone();
            {
                let tx = tx.clone();
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
                let tx = tx.clone();
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let events = tray_icon::TrayIconEvent::receiver();
                    while let Ok(event) = events.recv() {
                        match event {
                            tray_icon::TrayIconEvent::DoubleClick {
                                button: tray_icon::MouseButton::Left,
                                ..
                            }
                            | tray_icon::TrayIconEvent::Click {
                                button: tray_icon::MouseButton::Left,
                                button_state: tray_icon::MouseButtonState::Up,
                                ..
                            } => {
                                crate::util::app_log("tray-delivery: left click -> show");
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
    }

    /// Reflect the app state in the tray: color (gray stopped / green running /
    /// red degraded) and a tooltip with live counters.
    pub fn set_state(&self, rgb: [u8; 3], tooltip: &str) {
        #[cfg(windows)]
        {
            *self.state.lock().unwrap() = Some((rgb, tooltip.to_string()));
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::PostThreadMessageW(
                    self.tray_tid,
                    WM_APP_TRAY_STATE,
                    0,
                    0,
                );
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.icon.set_icon(Some(make_icon(rgb)));
            let _ = self.icon.set_tooltip(Some(tooltip));
        }
    }
    pub fn poll(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(action) = self.rx.try_recv() {
            actions.push(action);
        }
        actions
    }
}
