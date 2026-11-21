#![cfg_attr(windows, windows_subsystem = "windows")]

mod config;
mod engines;
mod install;
mod proxy;
mod subs;
mod tasks;
mod tray;
mod ui;
mod uris;
mod util;

fn listen_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--listen" {
            return args.next();
        }
        if let Some(rest) = a.strip_prefix("--listen=") {
            return Some(rest.to_string());
        }
    }
    None
}

/// A second instance would fight the first one over the shared sidecar pid file and
/// the profile temp directory, so refuse to start when one is already running.
#[cfg(windows)]
fn already_running() -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Local\\kubevpn-single-instance"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if h.is_null() {
            return false; // fail open rather than block startup
        }
        let exists = GetLastError() == ERROR_ALREADY_EXISTS;
        // HANDLE is a raw pointer with no Drop: the mutex is intentionally never
        // closed and lives until the process exits.
        let _ = h;
        exists
    }
}

#[cfg(windows)]
fn notify_duplicate() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
    let text: Vec<u16> = "kubevpn is already running."
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let caption: Vec<u16> = "kubevpn".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[cfg(unix)]
fn already_running() -> bool {
    use std::os::unix::net::{UnixListener, UnixStream};
    let path = std::env::temp_dir().join("kubevpn-single-instance.sock");
    match UnixListener::bind(&path) {
        Ok(l) => {
            std::mem::forget(l);
            false
        }
        Err(_) => {
            if UnixStream::connect(&path).is_ok() {
                true
            } else {
                // stale socket from a crashed run
                let _ = std::fs::remove_file(&path);
                match UnixListener::bind(&path) {
                    Ok(l) => {
                        std::mem::forget(l);
                        false
                    }
                    Err(_) => true,
                }
            }
        }
    }
}

#[cfg(unix)]
fn notify_duplicate() {
    eprintln!("kubevpn is already running");
}

fn main() -> eframe::Result<()> {
    if already_running() {
        notify_duplicate();
        return Ok(());
    }
    let listen = listen_arg();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_title("kubevpn"),
        ..Default::default()
    };
    eframe::run_native(
        "kubevpn",
        options,
        Box::new(move |cc| Ok(Box::new(ui::App::new(cc, listen.clone())))),
    )
}
