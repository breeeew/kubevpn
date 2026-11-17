use std::process::Child;
use std::sync::mpsc::{channel, Receiver, Sender};

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
}

/// Runs the slow parts (waiting for a sidecar port, downloading an engine) off the UI thread.
pub struct Tasks {
    tx: Sender<TaskResult>,
    rx: Receiver<TaskResult>,
}

impl Tasks {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self { tx, rx }
    }

    pub fn spawn_profile(&self, id: String, profile: Profile, bin: String, logs: Logs) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = crate::engines::spawn(&profile, &bin, &logs).map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Spawned { id, result });
        });
    }

    pub fn install(&self, key: String, logs: Logs) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = crate::install::install(&key, &logs).map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Installed { key, result });
        });
    }

    pub fn try_recv(&self) -> Option<TaskResult> {
        self.rx.try_recv().ok()
    }
}
