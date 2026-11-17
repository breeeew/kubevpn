use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

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
    /// Domain suffix and the local port to use; None means the target profile is not running.
    pub rules: Vec<(String, Option<u16>)>,
    /// Port for everything that matches no rule.
    pub default: Option<u16>,
    /// True when a default profile is configured, whether or not it is running.
    pub default_configured: bool,
    /// Refuse traffic instead of sending it direct when the target profile is not running.
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Direct,
    Via(u16),
    Blocked,
}

impl Routes {
    pub fn pick(&self, host: &str) -> Decision {
        let h = host.to_ascii_lowercase();
        for (suffix, port) in &self.rules {
            let s = suffix.trim_start_matches('.').to_ascii_lowercase();
            if h == s || h.ends_with(&format!(".{}", s)) {
                return match port {
                    Some(p) => Decision::Via(*p),
                    None if self.fail_closed => Decision::Blocked,
                    None => Decision::Direct,
                };
            }
        }
        match self.default {
            Some(p) => Decision::Via(p),
            None if self.default_configured && self.fail_closed => Decision::Blocked,
            None => Decision::Direct,
        }
    }
}

fn describe(decision: Decision) -> String {
    match decision {
        Decision::Direct => "direct".to_string(),
        Decision::Via(p) => format!("127.0.0.1:{}", p),
        Decision::Blocked => "blocked (target profile is down)".to_string(),
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
    [
        0x05,
        if ok { 0x00 } else { 0x01 },
        0x00,
        0x01,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
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
    if req[1] != 0x01 && req[1] != 0x03 {
        s.write_all(&socks_reply(false)).await?;
        bail!("only CONNECT and UDP ASSOCIATE are supported");
    }
    let host = read_stream_addr(&mut s, req[3]).await?;
    let mut pb = [0u8; 2];
    s.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    if req[1] == 0x03 {
        app_log("socks5 UDP ASSOCIATE");
        return udp_associate(s, routes, stats, logs).await;
    }

    let decision = routes.read().unwrap().pick(&host);
    app_log(&format!(
        "socks5 {}:{} -> {}",
        host,
        port,
        describe(decision)
    ));
    log(
        &logs,
        format!("socks {}:{} -> {}", host, port, describe(decision)),
    );
    if decision == Decision::Blocked {
        s.write_all(&socks_reply(false)).await?;
        log(
            &logs,
            format!("blocked {}:{} (target profile is not running)", host, port),
        );
        return Ok(());
    }
    let up = match decision {
        Decision::Via(p) => Some(p),
        _ => None,
    };

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

async fn read_stream_addr(s: &mut TcpStream, atyp: u8) -> Result<String> {
    Ok(match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
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
            Ipv6Addr::from(ip).to_string()
        }
        _ => bail!("bad address type"),
    })
}

fn socks_reply_addr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut v = vec![0x05, 0x00, 0x00, 0x01];
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v
        }
        SocketAddr::V6(a) => {
            let mut v = vec![0x05, 0x00, 0x00, 0x04];
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v
        }
    }
}

/// Splits a SOCKS5 UDP datagram: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
fn parse_udp_header(b: &[u8]) -> Option<(String, u16, &[u8])> {
    if b.len() < 4 || b[2] != 0 {
        // fragmented datagrams are not supported
        return None;
    }
    match b[3] {
        0x01 => {
            if b.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Some((ip.to_string(), u16::from_be_bytes([b[8], b[9]]), &b[10..]))
        }
        0x03 => {
            if b.len() < 5 {
                return None;
            }
            let l = b[4] as usize;
            if b.len() < 5 + l + 2 {
                return None;
            }
            let host = String::from_utf8_lossy(&b[5..5 + l]).to_string();
            let port = u16::from_be_bytes([b[5 + l], b[6 + l]]);
            Some((host, port, &b[7 + l..]))
        }
        0x04 => {
            if b.len() < 22 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[4..20]);
            Some((
                Ipv6Addr::from(o).to_string(),
                u16::from_be_bytes([b[20], b[21]]),
                &b[22..],
            ))
        }
        _ => None,
    }
}

fn build_udp_header(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0u8, 0u8];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&ip.octets());
    } else {
        let bytes = host.as_bytes();
        let len = bytes.len().min(255);
        out.push(0x03);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

struct Upstream {
    udp: Arc<UdpSocket>,
    relay: SocketAddr,
    _ctl: TcpStream,
}

/// Opens a SOCKS5 UDP association on a profile's local port.
async fn open_upstream(port: u16) -> Result<Upstream> {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await?;
    if method[1] != 0x00 {
        bail!("upstream requires authentication");
    }
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("upstream refused UDP ASSOCIATE (code {})", head[1]);
    }
    let host = read_stream_addr(&mut tcp, head[3]).await?;
    let mut pb = [0u8; 2];
    tcp.read_exact(&mut pb).await?;
    let relay_port = u16::from_be_bytes(pb);
    let relay_ip = if host == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else {
        host
    };
    let relay: SocketAddr = format!("{}:{}", relay_ip, relay_port)
        .parse()
        .map_err(|e| anyhow!("bad relay address: {}", e))?;
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    Ok(Upstream {
        udp,
        relay,
        _ctl: tcp,
    })
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::from((ip, port)));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::from((ip, port)));
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {}", host))
}

// The entry API cannot be used here: opening an upstream awaits while holding the map open.
#[allow(clippy::map_entry)]
async fn udp_associate(
    mut ctl: TcpStream,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
) -> Result<()> {
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let bound = client_sock.local_addr()?;
    ctl.write_all(&socks_reply_addr(bound)).await?;
    log(&logs, format!("udp associate on {}", bound));

    let direct = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    {
        let direct = direct.clone();
        let sock = client_sock.clone();
        let who = client.clone();
        let stats = stats.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, src)) = direct.recv_from(&mut buf).await {
                stats.out_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let target = *who.lock().unwrap();
                if let Some(target) = target {
                    let pkt = build_udp_header(&src.ip().to_string(), src.port(), &buf[..n]);
                    let _ = sock.send_to(&pkt, target).await;
                }
            }
        }));
    }

    let mut upstreams: HashMap<u16, Arc<UdpSocket>> = HashMap::new();
    let mut relays: HashMap<u16, SocketAddr> = HashMap::new();
    let mut upstream_ctl: HashMap<u16, TcpStream> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut sink = [0u8; 1];

    loop {
        tokio::select! {
            r = ctl.read(&mut sink) => match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            r = client_sock.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let known = {
                    let mut w = client.lock().unwrap();
                    if w.is_none() {
                        *w = Some(src);
                    }
                    *w == Some(src)
                };
                if !known {
                    continue;
                }
                let (host, port, payload) = match parse_udp_header(&buf[..n]) {
                    Some(v) => v,
                    None => continue,
                };
                stats.in_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let decision = routes.read().unwrap().pick(&host);
                match decision {
                    Decision::Blocked => {
                        log(
                            &logs,
                            format!("udp blocked {}:{} (target profile is not running)", host, port),
                        );
                    }
                    Decision::Direct => match resolve(&host, port).await {
                        Ok(dst) => {
                            let _ = direct.send_to(payload, dst).await;
                        }
                        Err(e) => log(&logs, format!("udp resolve {}: {}", host, e)),
                    },
                    Decision::Via(p) => {
                        if !upstreams.contains_key(&p) {
                            match open_upstream(p).await {
                                Ok(up) => {
                                    let sock = up.udp.clone();
                                    let cs = client_sock.clone();
                                    let who = client.clone();
                                    let stats = stats.clone();
                                    tasks.push(tokio::spawn(async move {
                                        let mut b = vec![0u8; 65535];
                                        while let Ok((n2, _)) = sock.recv_from(&mut b).await {
                                            stats.out_bytes.fetch_add(n2 as u64, Ordering::Relaxed);
                                            let target = *who.lock().unwrap();
                                            if let Some(target) = target {
                                                let _ = cs.send_to(&b[..n2], target).await;
                                            }
                                        }
                                    }));
                                    relays.insert(p, up.relay);
                                    upstreams.insert(p, up.udp);
                                    upstream_ctl.insert(p, up._ctl);
                                    log(&logs, format!("udp upstream via 127.0.0.1:{}", p));
                                    app_log(&format!("udp upstream via 127.0.0.1:{}", p));
                                }
                                Err(e) => {
                                    log(&logs, format!("udp upstream port {}: {}", p, e));
                                    app_log(&format!("udp upstream port {} failed: {}", p, e));
                                    continue;
                                }
                            }
                        }
                        if let (Some(sock), Some(relay)) = (upstreams.get(&p), relays.get(&p)) {
                            let pkt = build_udp_header(&host, port, payload);
                            let _ = sock.send_to(&pkt, *relay).await;
                        }
                    }
                }
            }
        }
    }

    for t in tasks {
        t.abort();
    }
    log(&logs, format!("udp associate on {} closed", bound));
    Ok(())
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("bad ipv6 target"))?;
        return Ok((
            host.to_string(),
            tail.trim_start_matches(':').parse::<u16>()?,
        ));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("no port in {}", s))?;
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
        let decision = routes.read().unwrap().pick(&host);
        app_log(&format!(
            "http-connect {}:{} -> {}",
            host,
            port,
            describe(decision)
        ));
        log(
            &logs,
            format!("http CONNECT {}:{} -> {}", host, port, describe(decision)),
        );
        if decision == Decision::Blocked {
            s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            log(
                &logs,
                format!("blocked {}:{} (target profile is not running)", host, port),
            );
            return Ok(());
        }
        let up = match decision {
            Decision::Via(p) => Some(p),
            _ => None,
        };
        match connect_via(&host, port, up).await {
            Ok(remote) => {
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                relay(s, remote, stats).await
            }
            Err(e) => {
                s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                log(
                    &logs,
                    format!("http CONNECT {}:{} failed: {}", host, port, e),
                );
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
        let decision = routes.read().unwrap().pick(&host);
        app_log(&format!(
            "http {} {}:{} -> {}",
            method,
            host,
            port,
            describe(decision)
        ));
        log(
            &logs,
            format!(
                "http {} {}:{} -> {}",
                method,
                host,
                port,
                describe(decision)
            ),
        );
        if decision == Decision::Blocked {
            s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            log(
                &logs,
                format!("blocked {}:{} (target profile is not running)", host, port),
            );
            return Ok(());
        }
        let up = match decision {
            Decision::Via(p) => Some(p),
            _ => None,
        };
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
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
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
#[cfg(test)]
mod tests {
    use super::*;

    fn table(
        rules: Vec<(&str, Option<u16>)>,
        default: Option<u16>,
        configured: bool,
        fail_closed: bool,
    ) -> Routes {
        Routes {
            rules: rules.into_iter().map(|(s, p)| (s.to_string(), p)).collect(),
            default,
            default_configured: configured,
            fail_closed,
        }
    }

    #[test]
    fn matches_exact_and_subdomain() {
        let r = table(vec![("example.com", Some(15001))], None, false, false);
        assert_eq!(r.pick("example.com"), Decision::Via(15001));
        assert_eq!(r.pick("api.example.com"), Decision::Via(15001));
        assert_eq!(r.pick("EXAMPLE.COM"), Decision::Via(15001));
    }

    #[test]
    fn does_not_match_lookalike_domain() {
        let r = table(vec![("example.com", Some(15001))], None, false, false);
        assert_eq!(r.pick("notexample.com"), Decision::Direct);
        assert_eq!(r.pick("example.com.evil.net"), Decision::Direct);
    }

    #[test]
    fn falls_back_to_direct_when_profile_is_down() {
        let r = table(vec![("example.com", None)], None, false, false);
        assert_eq!(r.pick("example.com"), Decision::Direct);
    }

    #[test]
    fn blocks_when_fail_closed_and_profile_is_down() {
        let r = table(vec![("example.com", None)], None, false, true);
        assert_eq!(r.pick("example.com"), Decision::Blocked);
    }

    #[test]
    fn default_route_applies_to_unknown_hosts() {
        let r = table(vec![], Some(15002), true, false);
        assert_eq!(r.pick("anything.test"), Decision::Via(15002));
    }

    #[test]
    fn default_down_respects_fail_closed() {
        let open = table(vec![], None, true, false);
        assert_eq!(open.pick("anything.test"), Decision::Direct);
        let closed = table(vec![], None, true, true);
        assert_eq!(closed.pick("anything.test"), Decision::Blocked);
    }

    #[test]
    fn udp_header_roundtrip_for_a_domain() {
        let pkt = build_udp_header("example.com", 53, b"payload");
        let (host, port, body) = parse_udp_header(&pkt).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 53);
        assert_eq!(body, b"payload");
    }

    #[test]
    fn udp_header_roundtrip_for_ipv4() {
        let pkt = build_udp_header("8.8.8.8", 5353, b"x");
        assert_eq!(pkt[3], 0x01);
        let (host, port, body) = parse_udp_header(&pkt).unwrap();
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 5353);
        assert_eq!(body, b"x");
    }

    #[test]
    fn udp_fragments_are_rejected() {
        let mut pkt = build_udp_header("example.com", 53, b"x");
        pkt[2] = 1;
        assert!(parse_udp_header(&pkt).is_none());
    }

    #[test]
    fn udp_truncated_packets_are_rejected() {
        assert!(parse_udp_header(&[0, 0, 0, 3]).is_none());
        assert!(parse_udp_header(&[0, 0, 0, 1, 1, 2]).is_none());
    }

    #[test]
    fn no_default_configured_is_always_direct() {
        let r = table(vec![], None, false, true);
        assert_eq!(r.pick("anything.test"), Decision::Direct);
    }
}
