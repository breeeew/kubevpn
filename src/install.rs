use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use crate::util::{app_log, log, proxy_from_env, Logs};

pub struct Engine {
    pub key: &'static str,
    pub repo: &'static str,
}

pub const ENGINES: [Engine; 3] = [
    Engine {
        key: "awg",
        repo: "bropines/awg-wireproxy",
    },
    Engine {
        key: "xray",
        repo: "XTLS/Xray-core",
    },
    Engine {
        key: "singbox",
        repo: "SagerNet/sing-box",
    },
];

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Clone)]
struct Asset {
    name: String,
    browser_download_url: String,
}

pub fn engine_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.unwrap_or_else(std::env::temp_dir)
        .join("kubevpn")
        .join("engines")
}

fn agent() -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .user_agent("kubevpn/0.1");
    if let Some(p) = proxy_from_env() {
        if let Ok(proxy) = ureq::Proxy::new(&p) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build()
}

fn get_text(url: &str) -> Result<String> {
    let resp = agent().get(url).call()?;
    Ok(resp.into_string()?)
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let resp = agent().get(url).call()?;
    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest)?;
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn arch_tag() -> &'static str {
    std::env::consts::ARCH
}

/// Pick the release asset that matches this platform for the given engine.
fn pick_asset(key: &str, assets: &[Asset]) -> Option<Asset> {
    let arch = arch_tag();
    let candidates: Vec<&Asset> = assets
        .iter()
        .filter(|a| {
            let n = a.name.to_lowercase();
            if !(n.ends_with(".zip") || n.ends_with(".tar.gz") || n.ends_with(".tgz")) {
                return false;
            }
            match key {
                "awg" => {
                    let want_os = if cfg!(windows) {
                        "windows"
                    } else if cfg!(target_os = "macos") {
                        "darwin"
                    } else {
                        "linux"
                    };
                    let want_arch = if arch == "aarch64" { "arm64" } else { "amd64" };
                    n.contains(want_os) && n.contains(want_arch)
                }
                "xray" => {
                    let want_os = if cfg!(windows) {
                        "windows"
                    } else if cfg!(target_os = "macos") {
                        "macos"
                    } else {
                        "linux"
                    };
                    let want_arch = if arch == "aarch64" { "arm64" } else { "-64" };
                    n.contains(want_os) && n.contains(want_arch)
                }
                "singbox" => {
                    let want_os = if cfg!(windows) {
                        "windows"
                    } else if cfg!(target_os = "macos") {
                        "darwin"
                    } else {
                        "linux"
                    };
                    let want_arch = if arch == "aarch64" { "arm64" } else { "amd64" };
                    n.contains(want_os) && n.contains(want_arch)
                }
                _ => false,
            }
        })
        .collect();
    // Prefer archives that are not "legacy"/"v1/v2/v3" variants unless those are all we have.
    let preferred = candidates
        .iter()
        .find(|a| {
            let n = a.name.to_lowercase();
            !n.contains("legacy") && !n.contains("-v1") && !n.contains("-v2") && !n.contains("-v3")
        })
        .copied()
        .or_else(|| candidates.first().copied());
    preferred.cloned()
}

fn sha256_of(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish_hex())
}

/// Minimal SHA-256, so the installer does not need an extra dependency.
struct Sha256 {
    state: [u32; 8],
    buf: Vec<u8>,
    len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Vec::new(),
            len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 {
            let block: Vec<u8> = self.buf.drain(..64).collect();
            self.compress(&block);
        }
    }

    fn compress(&mut self, block: &[u8]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finish_hex(mut self) -> String {
        let bit_len = self.len.wrapping_mul(8);
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());
        let blocks: Vec<u8> = self.buf.clone();
        for chunk in blocks.chunks(64) {
            let block: Vec<u8> = chunk.to_vec();
            self.compress(&block);
        }
        self.state.iter().map(|v| format!("{:08x}", v)).collect()
    }
}

fn extract(archive: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let name = archive
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if name.ends_with(".zip") {
        let file = std::fs::File::open(archive)?;
        let mut zip = zip::ZipArchive::new(file)?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let Some(rel) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
                continue;
            };
            let out = dest.join(rel);
            if entry.is_dir() {
                std::fs::create_dir_all(&out)?;
                continue;
            }
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&out)?;
            std::io::copy(&mut entry, &mut f)?;
        }
    } else {
        let file = std::fs::File::open(archive)?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(gz);
        ar.unpack(dest)?;
    }
    Ok(())
}

fn find_binary(dir: &Path, key: &str) -> Option<PathBuf> {
    let want = match key {
        "awg" => "wireproxy",
        "xray" => "xray",
        _ => "sing-box",
    };
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();
            let stem = name.trim_end_matches(".exe");
            if stem == want {
                return Some(p);
            }
        }
    }
    None
}

/// Download and unpack the latest release of an engine. Returns the path to the executable.
pub fn install(key: &str, logs: &Logs) -> Result<PathBuf> {
    let engine = ENGINES
        .iter()
        .find(|e| e.key == key)
        .ok_or_else(|| anyhow!("unknown engine {}", key))?;

    let api = format!(
        "https://api.github.com/repos/{}/releases/latest",
        engine.repo
    );
    log(logs, format!("checking {} releases", engine.repo));
    let release: Release =
        serde_json::from_str(&get_text(&api)?).context("parsing GitHub release")?;
    let asset = pick_asset(key, &release.assets).ok_or_else(|| {
        anyhow!(
            "no asset for this platform in {} {} (arch {})",
            engine.repo,
            release.tag_name,
            std::env::consts::ARCH
        )
    })?;
    log(
        logs,
        format!("{} {} -> {}", engine.repo, release.tag_name, asset.name),
    );

    let dir = engine_dir().join(key);
    std::fs::create_dir_all(&dir)?;
    let archive = dir.join(&asset.name);
    download(&asset.browser_download_url, &archive).context("downloading asset")?;

    // Verify the checksum when the release publishes one.
    let sums_url = format!(
        "https://github.com/{}/releases/download/{}/checksums.txt",
        engine.repo, release.tag_name
    );
    if let Ok(text) = get_text(&sums_url) {
        if let Some(expected) = text
            .lines()
            .find(|l| l.trim_end().ends_with(&asset.name))
            .and_then(|l| l.split_whitespace().next())
        {
            let actual = sha256_of(&archive)?;
            if expected.eq_ignore_ascii_case(&actual) {
                app_log(&format!("{}: checksum ok", asset.name));
                log(logs, "checksum ok");
            } else {
                app_log(&format!("{}: checksum mismatch", asset.name));
                bail!("checksum mismatch: expected {}, got {}", expected, actual);
            }
        }
    }

    extract(&archive, &dir).context("unpacking archive")?;
    let binary =
        find_binary(&dir, key).ok_or_else(|| anyhow!("binary not found in the archive"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755));
    }

    let _ = std::fs::remove_file(&archive);
    app_log(&format!("installed {} at {}", key, binary.display()));
    log(logs, format!("{} installed: {}", key, binary.display()));
    Ok(binary)
}
