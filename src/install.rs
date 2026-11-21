use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

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
        .user_agent("kubevpn/0.2");
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
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Find the expected SHA-256 for an asset in a "sums" style file
/// (checksums.txt / sha256sum.txt: "<hex>  <name>" per line).
fn sum_for_asset(text: &str, asset_name: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim_end().ends_with(asset_name))
        .and_then(|l| l.split_whitespace().next())
        .map(|s| s.to_string())
}

/// Verify the downloaded archive against whatever the release publishes:
/// checksums.txt (awg-wireproxy), sha256sum.txt (sing-box) or a per-asset
/// .dgst file with "SHA256= ..." lines (Xray-core). Returns whether a checksum
/// was actually verified; a missing checksum is a visible warning, not silence.
fn verify_checksum(
    repo: &str,
    tag: &str,
    asset_name: &str,
    archive: &Path,
    logs: &Logs,
) -> Result<bool> {
    let base = format!("https://github.com/{}/releases/download/{}", repo, tag);
    let mut expected: Option<String> = None;
    for sums in ["checksums.txt", "sha256sum.txt"] {
        if let Ok(text) = get_text(&format!("{}/{}", base, sums)) {
            if let Some(sum) = sum_for_asset(&text, asset_name) {
                expected = Some(sum);
                break;
            }
        }
    }
    if expected.is_none() {
        if let Ok(text) = get_text(&format!("{}/{}.dgst", base, asset_name)) {
            for line in text.lines() {
                let kv = line.split_once('=').or_else(|| line.split_once(':'));
                if let Some((k, v)) = kv {
                    if k.trim().eq_ignore_ascii_case("SHA256") {
                        expected = Some(v.trim().to_string());
                        break;
                    }
                }
            }
        }
    }
    match expected {
        Some(expected) => {
            let actual = sha256_of(archive)?;
            if expected.eq_ignore_ascii_case(&actual) {
                app_log(&format!("{}: checksum ok", asset_name));
                log(logs, "checksum ok");
                Ok(true)
            } else {
                app_log(&format!("{}: checksum mismatch", asset_name));
                bail!("checksum mismatch: expected {}, got {}", expected, actual)
            }
        }
        None => {
            let msg = format!(
                "{}: no checksum published by the release, verified by HTTPS only",
                asset_name
            );
            app_log(&msg);
            log(logs, msg);
            Ok(false)
        }
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

/// Download and unpack the latest release of an engine into a per-version directory
/// (engines/<key>/<tag>/), so a running binary is never overwritten and previous
/// versions stay available for rollback. Returns the path to the executable.
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

    let tag: String = release
        .tag_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = engine_dir().join(key).join(&tag);
    std::fs::create_dir_all(&dir)?;
    let archive = dir.join(&asset.name);
    download(&asset.browser_download_url, &archive).context("downloading asset")?;

    verify_checksum(engine.repo, &release.tag_name, &asset.name, &archive, logs)?;

    extract(&archive, &dir).context("unpacking archive")?;
    let binary =
        find_binary(&dir, key).ok_or_else(|| anyhow!("binary not found in the archive"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755));
    }

    let _ = std::fs::remove_file(&archive);
    app_log(&format!(
        "installed {} {} at {}",
        key,
        release.tag_name,
        binary.display()
    ));
    log(
        logs,
        format!(
            "{} {} installed: {}",
            key,
            release.tag_name,
            binary.display()
        ),
    );
    Ok(binary)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_file_matching() {
        let text = "abc123  other.zip\ndef456  Xray-windows-64.zip\n";
        assert_eq!(
            sum_for_asset(text, "Xray-windows-64.zip").as_deref(),
            Some("def456")
        );
        assert_eq!(sum_for_asset(text, "missing.zip"), None);
    }
}
