use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::util::{app_log, log, Logs};

#[derive(Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub active: AtomicU64,
    pub in_bytes: AtomicU64,
    pub out_bytes: AtomicU64,
}

#[derive(Clone, Default)]
pub struct Routes {
    pub rules: Vec<(String, u16)>,
    pub default: Option<u16>,
}

impl Routes {
    pub fn pick(&self, host: &str) -> Option<u16> {
        let h = host.to_ascii_lowercase();
        for (suffix, port) in &self.rules {
            let s = suffix.trim_start_matches('.').to_ascii_lowercase();
            if h == s || h.ends_with(&format!(".{}", s)) {
                return Some(*port);
            }
        }
        self.default
    }
}

fn describe(up: Option<u16>) -> String {
    match up {
        None => "direct".to_string(),
        Some(p) => format!("127.0.0.1:{}", p),
    }
}

enum Mode {
    Socks5,
    Socks4,
    Http,
}

async fn sniff_mode(s: &TcpStream) -> Result<Mode> {
    let mut buf = [0u8; 1];
    let n = s.peek(&mut buf).await?;
    if n == 0 {
        bail!("closed before first byte");
    }
    Ok(match buf[0] {
        0x05 => Mode::Socks5,
        0x04 => Mode::Socks4,
        _ => Mode::Http,
    })
}

async fn connect_via(host: &str, port: u16, upstream: Option<u16>) -> Result<TcpStream> {
    match upstream {
        None => Ok(TcpStream::connect((host, port)).await?),
        Some(up_port) => {
            let mut s = TcpStream::connect(("127.0.0.1", up_port)).await?;
            s.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut resp = [0u8; 2];
            s.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                bail!("upstream requires auth");
            }
            let hb = host.as_bytes();
            if hb.len() > 255 {
                bail!("host too long");
            }
            let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
            req.extend_from_slice(hb);
            req.extend_from_slice(&port.to_be_bytes());
            s.write_all(&req).await?;
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await?;
            if head[1] != 0x00 {
                bail!("upstream refused: code {}", head[1]);
            }
            let skip = match head[3] {
                0x01 => 4,
                0x03 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).await?;
                    l[0] as usize
                }
                0x04 => 16,
                _ => bail!("bad reply"),
            };
            let mut rest = vec![0u8; skip + 2];
            s.read_exact(&mut rest).await?;
            Ok(s)
        }
    }
}

async fn relay(mut a: TcpStream, mut b: TcpStream, stats: Arc<Stats>) -> Result<()> {
    let (up, down) = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
    stats.in_bytes.fetch_add(up, Ordering::Relaxed);
    stats.out_bytes.fetch_add(down, Ordering::Relaxed);
    Ok(())
}

fn socks_reply(ok: bool) -> [u8; 10] {
    [0x05, if ok { 0x00 } else { 0x01 }, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

async fn handle_socks(
    mut s: TcpStream,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
) -> Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("bad socks version");
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    s.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        s.write_all(&socks_reply(false)).await?;
        bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8(d)?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            s.write_all(&socks_reply(false)).await?;
            bail!("bad address type");
        }
    };
    let mut pb = [0u8; 2];
    s.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    let up = routes.read().unwrap().pick(&host);
    app_log(&format!("socks5 {}:{} -> {}", host, port, describe(up)));
    log(&logs, format!("socks {}:{} -> {}", host, port, describe(up)));

    match connect_via(&host, port, up).await {
        Ok(remote) => {
            s.write_all(&socks_reply(true)).await?;
            relay(s, remote, stats).await
        }
        Err(e) => {
            s.write_all(&socks_reply(false)).await?;
            log(&logs, format!("socks {}:{} failed: {}", host, port, e));
            Err(e)
        }
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(|| anyhow!("bad ipv6 target"))?;
        return Ok((host.to_string(), tail.trim_start_matches(':').parse::<u16>()?));
    }
    let (host, port) = s.rsplit_once(':').ok_or_else(|| anyhow!("no port in {}", s))?;
    Ok((host.to_string(), port.parse::<u16>()?))
}

async fn handle_http(
    mut s: TcpStream,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("closed while reading request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("request too large");
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let first = head.lines().next().unwrap_or("").to_string();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target)?;
        let up = routes.read().unwrap().pick(&host);
        app_log(&format!("http-connect {}:{} -> {}", host, port, describe(up)));
        log(&logs, format!("http CONNECT {}:{} -> {}", host, port, describe(up)));
        match connect_via(&host, port, up).await {
            Ok(remote) => {
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                relay(s, remote, stats).await
            }
            Err(e) => {
                s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                log(&logs, format!("http CONNECT {}:{} failed: {}", host, port, e));
                Err(e)
            }
        }
    } else {
        let rest = target
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only CONNECT and absolute http:// are supported"))?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{}", p)),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
            None => (authority.to_string(), 80u16),
        };
        let up = routes.read().unwrap().pick(&host);
        app_log(&format!("http {} {}:{} -> {}", method, host, port, describe(up)));
        log(&logs, format!("http {} {}:{} -> {}", method, host, port, describe(up)));
        let mut remote = connect_via(&host, port, up).await?;
        let mut out = format!("{} {} HTTP/1.1\r\n", method, path);
        for line in head.lines().skip(1) {
            if line.is_empty() || line.to_ascii_lowercase().starts_with("proxy-connection") {
                continue;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        remote.write_all(out.as_bytes()).await?;
        relay(s, remote, stats).await
    }
}

pub fn start(
    listen: String,
    routes: Arc<RwLock<Routes>>,
    logs: Logs,
    stats: Arc<Stats>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                log(&logs, format!("runtime error: {}", e));
                alive.store(false, Ordering::SeqCst);
                return;
            }
        };
        let alive2 = alive.clone();
        rt.block_on(async move {
            let listener = match TcpListener::bind(&listen).await {
                Ok(l) => l,
                Err(e) => {
                    log(&logs, format!("bind {} failed: {}", listen, e));
                    alive2.store(false, Ordering::SeqCst);
                    return;
                }
            };
            log(&logs, format!("mixed listener on {}", listen));

            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
                let (stream, _peer) = match accepted {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        log(&logs, format!("accept error: {}", e));
                        continue;
                    }
                    Err(_) => continue,
                };
                stats.conns.fetch_add(1, Ordering::Relaxed);
                stats.active.fetch_add(1, Ordering::Relaxed);

                let routes = routes.clone();
                let stats2 = stats.clone();
                let logs2 = logs.clone();
                tokio::spawn(async move {
                    let res = match sniff_mode(&stream).await {
                        Ok(Mode::Socks5) => handle_socks(stream, routes, stats2.clone(), logs2.clone()).await,
                        Ok(Mode::Http) => handle_http(stream, routes, stats2.clone(), logs2.clone()).await,
                        Ok(Mode::Socks4) => {
                            let msg = "SOCKS4 is not supported (it resolves DNS locally) - use HTTP proxy or SOCKS5";
                            log(&logs2, msg);
                            app_log(msg);
                            Err(anyhow!("socks4 unsupported"))
                        }
                        Err(e) => Err(e),
                    };
                    if let Err(e) = res {
                        let m = e.to_string();
                        if !m.contains("closed") && !m.contains("only CONNECT") {
                            log(&logs2, format!("error: {}", m));
                        }
                    }
                    stats2.active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            log(&logs, "listener stopped");
        });
        alive.store(false, Ordering::SeqCst);
    });
}
