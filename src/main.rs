#![windows_subsystem = "windows"]

mod config;
mod engines;
mod proxy;
mod ui;
mod util;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_title("kubevpn"),
        ..Default::default()
    };
    eframe::run_native(
        "kubevpn",
        options,
        Box::new(|cc| Ok(Box::new(ui::App::new(cc)))),
    )
}
