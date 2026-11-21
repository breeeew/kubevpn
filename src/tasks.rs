use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Child;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::config::Profile;
use crate::util::Logs;

pub enum TaskResult {
    Spawned {
        id: String,
        result: Result<Child, String>,
    },
    Installed {
        key: String,
        result: Result<std::path::PathBuf, String>,
    },
    Refreshed {
        id: String,
        result: Result<Vec<crate::subs::Item>, String>,
    },
    /// Health probe: Ok(latency_ms) or Err(reason).
    Probed {
        id: String,
        result: Result<u64, String>,
    },
}

/// Runs the slow parts (waiting for a sidecar port, downloading an engine, probing
/// a tunnel) off the UI thread. Every result also wakes the egui loop, so the app
/// does not need a periodic repaint timer to notice background work.
pub struct Tasks {
    tx: Sender<TaskResult>,
    rx: Receiver<TaskResult>,
    ctx: egui::Context,
}

impl Tasks {
    pub fn new(ctx: egui::Context) -> Self {
        let (tx, rx) = channel();
        Self { tx, rx, ctx }
    }

    fn sender(&self) -> (Sender<TaskResult>, egui::Context) {
        (self.tx.clone(), self.ctx.clone())
    }

    pub fn spawn_profile(&self, id: String, profile: Profile, bin: String, logs: Logs) {
        let (tx, ctx) = self.sender();
        std::thread::spawn(move || {
            let result = crate::engines::spawn(&profile, &bin, &logs).map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Spawned { id, result });
            ctx.request_repaint();
        });
    }

    pub fn install(&self, key: String, logs: Logs) {
        let (tx, ctx) = self.sender();
        std::thread::spawn(move || {
            let result = crate::install::install(&key, &logs).map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Installed { key, result });
            ctx.request_repaint();
        });
    }

    pub fn refresh(&self, id: String, url: String, logs: Logs) {
        let (tx, ctx) = self.sender();
        std::thread::spawn(move || {
            let result = crate::subs::fetch(&url, &logs)
                .and_then(|body| crate::subs::parse(&body))
                .map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Refreshed { id, result });
            ctx.request_repaint();
        });
    }

    pub fn probe(&self, id: String, port: u16, target: Option<String>) {
        let (tx, ctx) = self.sender();
        std::thread::spawn(move || {
            let result = probe_inner(port, target).map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Probed { id, result });
            ctx.request_repaint();
        });
    }

    pub fn try_recv(&self) -> Option<TaskResult> {
        self.rx.try_recv().ok()
    }
}

/// SOCKS5 handshake with the sidecar, optionally followed by a CONNECT to the probe
/// target through the tunnel. Blocking IO with hard timeouts; never touches the mixed
/// port, only the profile's own local port.
fn probe_inner(port: u16, target: Option<String>) -> Result<u64> {
    let start = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    if m != [0x05, 0x00] {
        bail!("sidecar did not accept the SOCKS greeting");
    }
    if let Some(t) = target {
        let (host, port_str) = t
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad probe target {}", t))?;
        let port: u16 = port_str.parse()?;
        let hb = host.as_bytes();
        if hb.len() > 255 {
            bail!("probe host too long");
        }
        let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req)?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head)?;
        if head[1] != 0x00 {
            bail!("tunnel refused the probe connect (code {})", head[1]);
        }
        let skip = match head[3] {
            0x01 => 4,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l)?;
                l[0] as usize
            }
            0x04 => 16,
            _ => bail!("bad probe reply"),
        };
        let mut rest = vec![0u8; skip + 2];
        s.read_exact(&mut rest)?;
    }
    Ok(start.elapsed().as_millis() as u64)
}
