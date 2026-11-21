use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::config::Profile;
use crate::util::{app_log, hide_console, log, now_secs, strip_ansi, Logs};

pub fn profile_dir() -> PathBuf {
    std::env::temp_dir().join("kubevpn-profiles")
}

pub fn awg_effective(text: &str, port: u16) -> String {
    let mut out = String::new();
    let mut skip = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            let name = t
                .trim_matches(|c| c == '[' || c == ']')
                .to_ascii_lowercase();
            skip = name == "socks5" || name == "http";
            if skip {
                continue;
            }
        }
        if skip {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!("\n[Socks5]\nBindAddress = 127.0.0.1:{}\n", port));
    out
}

pub fn xray_effective(text: &str, port: u16) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(text)?;
    v["inbounds"] = serde_json::json!([{
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "socks",
        "settings": { "auth": "noauth", "udp": true },
        "sniffing": { "enabled": true, "destOverride": ["http", "tls"], "routeOnly": false },
        "tag": "mixed-in"
    }]);
    Ok(serde_json::to_string_pretty(&v)?)
}

pub fn singbox_effective(text: &str, port: u16) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(text)?;
    v["inbounds"] = serde_json::json!([{
        "type": "socks",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": port
    }]);
    Ok(serde_json::to_string_pretty(&v)?)
}

pub fn write_profile_file(p: &Profile) -> Result<PathBuf> {
    let dir = profile_dir();
    std::fs::create_dir_all(&dir)?;
    let ext = if p.kind == "awg" { "conf" } else { "json" };
    let path = dir.join(format!("{}.{}", p.id, ext));
    let text = match p.kind.as_str() {
        "awg" => awg_effective(&p.text, p.port),
        "singbox" => singbox_effective(&p.text, p.port)?,
        _ => xray_effective(&p.text, p.port)?,
    };
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Remove generated engine configs (they contain private keys) but keep sidecar logs
/// for post-mortem. Called on stop and on app exit.
pub fn clean_profile_configs() {
    let dir = profile_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension()
            .map(|x| x == "conf" || x == "json")
            .unwrap_or(false)
        {
            let _ = std::fs::remove_file(&p);
        }
    }
}

fn pids_file() -> PathBuf {
    std::env::temp_dir().join("kubevpn-sidecars.txt")
}

/// Record "name pid spawn_unix". The spawn timestamp guards against PID reuse:
/// a recycled PID belonging to an unrelated process (e.g. another app's xray)
/// will have a different start time and is never killed.
pub fn record_pid(name: &str, pid: u32, spawned_at: u64) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(pids_file())
    {
        let _ = writeln!(f, "{} {} {}", name, pid, spawned_at);
    }
}

/// Kill sidecars left behind by a previous (possibly crashed) run.
/// Uses sysinfo, so it works the same on every supported platform.
pub fn kill_stale_sidecars(logs: &Logs) {
    let mut killed = 0;
    if let Ok(text) = std::fs::read_to_string(pids_file()) {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let _name = it.next().unwrap_or("");
            let pid = it.next().and_then(|s| s.parse::<u32>().ok());
            let spawned = it.next().and_then(|s| s.parse::<u64>().ok());
            let (Some(pid), Some(spawned)) = (pid, spawned) else {
                continue; // legacy two-field entries cannot be verified safely
            };
            if let Some(proc_) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let pname = proc_.name().to_string_lossy().to_lowercase();
                let is_sidecar = pname.contains("wireproxy")
                    || pname.contains("xray")
                    || pname.contains("sing-box");
                let start_ok = proc_.start_time().abs_diff(spawned) <= 5;
                if is_sidecar && start_ok {
                    proc_.kill();
                    killed += 1;
                }
            }
        }
    }
    let _ = std::fs::remove_file(pids_file());
    if killed > 0 {
        log(logs, format!("cleaned {} stale sidecar(s)", killed));
    }
}

pub fn clear_pid_file() {
    let _ = std::fs::remove_file(pids_file());
}

/// Windows job object with KILL_ON_JOB_CLOSE: when kubevpn exits for any reason
/// (including a crash or Task Manager kill), the OS closes the job handle and every
/// assigned sidecar is terminated automatically. The handle lives for the whole
/// process lifetime in a OnceLock and is never closed explicitly.
#[cfg(windows)]
mod job {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    static JOB: OnceLock<isize> = OnceLock::new();

    fn handle() -> Option<isize> {
        let h = *JOB.get_or_init(|| unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return 0;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                return 0;
            }
            h as isize
        });
        if h == 0 {
            None
        } else {
            Some(h)
        }
    }

    pub fn assign(child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        if let Some(h) = handle() {
            unsafe {
                AssignProcessToJobObject(h as *mut std::ffi::c_void, child.as_raw_handle());
            }
        }
    }
}

#[cfg(not(windows))]
mod job {
    pub fn assign(_child: &std::process::Child) {}
}

pub fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Start a sidecar for the profile and wait until its local port is open.
pub fn spawn(p: &Profile, bin: &str, logs: &Logs) -> Result<Child> {
    if bin.trim().is_empty() {
        bail!("binary path for {} is not set", p.kind);
    }
    if !Path::new(bin).exists() {
        bail!("binary not found: {}", bin);
    }
    if std::net::TcpStream::connect(("127.0.0.1", p.port)).is_ok() {
        bail!("port {} is already in use", p.port);
    }
    let cfg_file = write_profile_file(p)?;
    let log_path = cfg_file.with_extension("log");
    let out = std::fs::File::create(&log_path)?;
    let err = out.try_clone()?;

    let mut cmd = Command::new(bin);
    if p.kind == "singbox" {
        cmd.arg("run").arg("-c").arg(&cfg_file);
    } else {
        cmd.arg("-c").arg(&cfg_file);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    hide_console(&mut cmd);

    let mut child = cmd.spawn()?;
    job::assign(&child);
    let bin_name = Path::new(bin)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    record_pid(&bin_name, child.id(), now_secs());

    if wait_port(p.port, Duration::from_secs(10)) {
        log(logs, format!("{} ({}:{}) up", p.name, p.kind, p.port));
        Ok(child)
    } else {
        let _ = child.kill();
        let _ = child.wait();
        let tail = std::fs::read_to_string(&log_path).unwrap_or_default();
        let hint: Vec<&str> = tail.lines().rev().take(2).collect();
        let hint: String = hint.into_iter().rev().collect::<Vec<_>>().join(" | ");
        app_log(&format!("{} failed: {}", p.name, hint));
        bail!(
            "{} did not open port {}: {}",
            p.name,
            p.port,
            strip_ansi(hint.trim())
        )
    }
}
