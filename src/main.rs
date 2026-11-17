#![windows_subsystem = "windows"]

mod config;
mod engines;
mod proxy;
mod ui;
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

fn main() -> eframe::Result<()> {
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
