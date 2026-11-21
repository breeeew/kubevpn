use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::util::{app_log, b64_decode, log, Logs};

// Timeouts apply to handshakes and to waiting for the next request/response head.
// Established relays deliberately have NO idle timeout: kubectl watches, logs -f and
// exec streams can stay silent for a long time and must not be cut.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(12);
const RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(60);
const KEEPALIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HEAD: usize = 64 * 1024;

#[derive(Default, Clone, Copy)]
pub struct PortStats {
    pub conns: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

#[derive(Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub active: AtomicU64,
    pub in_bytes: AtomicU64,
    pub out_bytes: AtomicU64,
    /// Per destination: profile port, or 0 for direct traffic.
    pub per_port: Mutex<HashMap<u16, PortStats>>,
}

impl Stats {
    fn conn(&self, key: u16) {
        self.per_port.lock().unwrap().entry(key).or_default().conns += 1;
    }

    fn add(&self, key: u16, up: u64, down: u64) {
        let mut m = self.per_port.lock().unwrap();
        let e = m.entry(key).or_default();
        e.in_bytes += up;
        e.out_bytes += down;
    }

    pub fn port_snapshot(&self, key: u16) -> PortStats {
        self.per_port
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .unwrap_or_default()
    }
}

#[derive(Clone)]
enum Matcher {
    /// suffix is lowercase without a leading dot; dotted is ".suffix".
    Domain {
        suffix: String,
        dotted: String,
    },
    Ip {
        addr: IpAddr,
        prefix: u8,
    },
}

#[derive(Clone)]
struct CompiledRule {
    matcher: Matcher,
    /// Specificity: suffix length or prefix length; the longest match wins.
    len: usize,
    port: Option<u16>,
}

#[derive(Clone, Default)]
pub struct Routes {
    rules: Vec<CompiledRule>,
    /// Port for everything that matches no rule.
    pub default: Option<u16>,
    /// True when a default profile is configured, whether or not it is running.
    pub default_configured: bool,
    /// Refuse traffic instead of sending it direct when the target profile is not running.
    pub fail_closed: bool,
    /// Credentials required on the mixed port, if any.
    pub auth: Option<(String, String)>,
    /// Log every request (window log + app log).
    pub log_requests: bool,
}

fn compile_rule(raw: &str, port: Option<u16>) -> Option<CompiledRule> {
    let s = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    // IP or CIDR?
    let (addr_part, prefix_part) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s.as_str(), None),
    };
    if let Ok(addr) = addr_part.parse::<IpAddr>() {
        let bits: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => match p.parse::<u8>() {
                Ok(v) if v <= bits => v,
                _ => return None,
            },
            None => bits,
        };
        return Some(CompiledRule {
            matcher: Matcher::Ip { addr, prefix },
            len: prefix as usize,
            port,
        });
    }
    if prefix_part.is_some() {
        return None; // "example.com/24" is not a thing
    }
    let len = s.len();
    Some(CompiledRule {
        matcher: Matcher::Domain {
            dotted: format!(".{}", s),
            suffix: s,
        },
        len,
        port,
    })
}

fn ip_in_net(addr: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Direct,
    Via(u16),
    Blocked,
}

impl Routes {
    pub fn build(
        raw_rules: Vec<(String, Option<u16>)>,
        default: Option<u16>,
        default_configured: bool,
        fail_closed: bool,
        auth: Option<(String, String)>,
        log_requests: bool,
    ) -> Self {
        let rules = raw_rules
            .iter()
            .filter_map(|(s, p)| compile_rule(s, *p))
            .collect();
        Self {
            rules,
            default,
            default_configured,
            fail_closed,
            auth,
            log_requests,
        }
    }

    fn decision(&self, port: Option<u16>, configured: bool) -> Decision {
        match port {
            Some(p) => Decision::Via(p),
            None if configured && self.fail_closed => Decision::Blocked,
            None => Decision::Direct,
        }
    }

    /// Longest match wins: a more specific suffix or a longer IP prefix beats a
    /// broader one regardless of the order rules were added in.
    pub fn pick(&self, host: &str) -> Decision {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let mut best: Option<(usize, Option<u16>)> = None;
        if let Ok(ip) = h.parse::<IpAddr>() {
            for r in &self.rules {
                if let Matcher::Ip { addr, prefix } = &r.matcher {
                    if ip_in_net(*addr, *prefix, ip) && best.is_none_or(|(l, _)| r.len > l) {
                        best = Some((r.len, r.port));
                    }
                }
            }
        } else {
            for r in &self.rules {
                if let Matcher::Domain { suffix, dotted } = &r.matcher {
                    if (h == *suffix || h.ends_with(dotted.as_str()))
                        && best.is_none_or(|(l, _)| r.len > l)
                    {
                        best = Some((r.len, r.port));
                    }
                }
            }
        }
        match best {
            Some((_, port)) => self.decision(port, true),
            None => self.decision(self.default, self.default_configured),
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

fn key_of(decision: Decision) -> u16 {
    match decision {
        Decision::Via(p) => p,
        _ => 0,
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

async fn connect_via_inner(host: &str, port: u16, upstream: Option<u16>) -> Result<TcpStream> {
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

async fn connect_via(host: &str, port: u16, upstream: Option<u16>) -> Result<TcpStream> {
    match tokio::time::timeout(UPSTREAM_TIMEOUT, connect_via_inner(host, port, upstream)).await {
        Ok(r) => r,
        Err(_) => bail!("connect to {}:{} timed out", host, port),
    }
}

/// AsyncWrite wrapper that counts bytes live, so per-profile counters move while
/// a connection is open (kubectl watches can stay open for hours).
struct Counting<W> {
    inner: W,
    stats: Arc<Stats>,
    key: u16,
    up: bool,
}

impl<W: AsyncWriteExt + Unpin> AsyncWrite for Counting<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            let n = *n as u64;
            if self.up {
                self.stats.in_bytes.fetch_add(n, Ordering::Relaxed);
                self.stats.add(self.key, n, 0);
            } else {
                self.stats.out_bytes.fetch_add(n, Ordering::Relaxed);
                self.stats.add(self.key, 0, n);
            }
        }
        r
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn relay(a: TcpStream, b: TcpStream, stats: Arc<Stats>, key: u16) -> Result<()> {
    let (mut ar, aw) = tokio::io::split(a);
    let (mut br, bw) = tokio::io::split(b);
    let mut cw_b = Counting {
        inner: bw,
        stats: stats.clone(),
        key,
        up: true,
    };
    let mut cw_a = Counting {
        inner: aw,
        stats: stats.clone(),
        key,
        up: false,
    };
    // Like copy_bidirectional, propagate half-close: when one direction hits EOF,
    // shut down the opposite write side so the peer sees FIN.
    let up = async {
        let r = tokio::io::copy(&mut ar, &mut cw_b).await;
        let _ = cw_b.inner.shutdown().await;
        r
    };
    let down = async {
        let r = tokio::io::copy(&mut br, &mut cw_a).await;
        let _ = cw_a.inner.shutdown().await;
        r
    };
    let (u, d) = tokio::join!(up, down);
    u?;
    d?;
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

/// Method negotiation + optional RFC1929 auth + CONNECT/UDP-ASSOCIATE request.
async fn socks_request(
    s: &mut TcpStream,
    auth: &Option<(String, String)>,
) -> Result<(String, u16, u8)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("bad socks version");
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    let want = if auth.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&want) {
        s.write_all(&[0x05, 0xff]).await?;
        bail!("no acceptable socks auth method");
    }
    s.write_all(&[0x05, want]).await?;
    if let Some((user, pass)) = auth {
        let mut vh = [0u8; 2];
        s.read_exact(&mut vh).await?;
        if vh[0] != 0x01 {
            bail!("bad auth subnegotiation version");
        }
        let mut u = vec![0u8; vh[1] as usize];
        s.read_exact(&mut u).await?;
        let mut pl = [0u8; 1];
        s.read_exact(&mut pl).await?;
        let mut p = vec![0u8; pl[0] as usize];
        s.read_exact(&mut p).await?;
        if u == user.as_bytes() && p == pass.as_bytes() {
            s.write_all(&[0x01, 0x00]).await?;
        } else {
            s.write_all(&[0x01, 0x01]).await?;
            bail!("socks auth failed");
        }
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] != 0x01 && req[1] != 0x03 {
        s.write_all(&socks_reply(false)).await?;
        bail!("only CONNECT and UDP ASSOCIATE are supported");
    }
    let host = read_stream_addr(s, req[3]).await?;
    let mut pb = [0u8; 2];
    s.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    Ok((host, port, req[1]))
}

async fn handle_socks(
    mut s: TcpStream,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
) -> Result<()> {
    let (auth, log_requests) = {
        let r = routes.read().unwrap();
        (r.auth.clone(), r.log_requests)
    };
    let (host, port, cmd) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, socks_request(&mut s, &auth)).await {
            Ok(r) => r?,
            Err(_) => bail!("socks handshake timed out"),
        };

    if cmd == 0x03 {
        if log_requests {
            app_log("socks5 UDP ASSOCIATE");
        }
        return udp_associate(s, routes, stats, logs).await;
    }

    let decision = routes.read().unwrap().pick(&host);
    if log_requests {
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
    }
    if decision == Decision::Blocked {
        s.write_all(&socks_reply(false)).await?;
        log(
            &logs,
            format!("blocked {}:{} (target profile is not running)", host, port),
        );
        return Ok(());
    }
    let key = key_of(decision);
    stats.conn(key);
    let up = match decision {
        Decision::Via(p) => Some(p),
        _ => None,
    };

    match connect_via(&host, port, up).await {
        Ok(remote) => {
            s.write_all(&socks_reply(true)).await?;
            relay(s, remote, stats, key).await
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
async fn open_upstream_inner(port: u16) -> Result<Upstream> {
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

async fn open_upstream(port: u16) -> Result<Upstream> {
    match tokio::time::timeout(UPSTREAM_TIMEOUT, open_upstream_inner(port)).await {
        Ok(r) => r,
        Err(_) => bail!("UDP ASSOCIATE on port {} timed out", port),
    }
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
                stats.add(0, 0, n as u64);
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
                stats.add(key_of(decision), n as u64, 0);
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
                                            stats.add(p, 0, n2 as u64);
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
            },
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

/// Read until \r\n\r\n, scanning only freshly arrived bytes (amortized linear).
/// Returns the whole buffer and the offset of the terminator.
async fn read_head(s: &mut TcpStream, wait: Duration) -> Result<(Vec<u8>, usize)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut scanned = 0usize;
    loop {
        let n = match tokio::time::timeout(wait, s.read(&mut tmp)).await {
            Ok(r) => r?,
            Err(_) => bail!("timed out reading head"),
        };
        if n == 0 {
            bail!("closed while reading head");
        }
        buf.extend_from_slice(&tmp[..n]);
        let start = scanned.saturating_sub(3);
        if let Some(pos) = buf[start..].windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok((buf, start + pos));
        }
        scanned = buf.len();
        if buf.len() > MAX_HEAD {
            bail!("request too large");
        }
    }
}

fn parse_head_lines(bytes: &[u8]) -> (String, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    (first, headers)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    header(headers, name)
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
        .unwrap_or(false)
}

fn http_authorized(headers: &[(String, String)], auth: &Option<(String, String)>) -> bool {
    let Some((user, pass)) = auth else {
        return true;
    };
    let Some(value) = header(headers, "proxy-authorization") else {
        return false;
    };
    let Some(b64) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    b64_decode(b64.trim())
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s == format!("{}:{}", user, pass))
        .unwrap_or(false)
}

const HOP_BY_HOP: [&str; 7] = [
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

/// Buffered reader over the origin connection so response framing can be parsed
/// without losing bytes that belong to the body.
struct Reader {
    s: TcpStream,
    buf: Vec<u8>,
    pos: usize,
}

impl Reader {
    fn new(s: TcpStream, initial: Vec<u8>) -> Self {
        Self {
            s,
            buf: initial,
            pos: 0,
        }
    }

    fn remaining(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn into_stream(self) -> TcpStream {
        debug_assert!(self.remaining().is_empty(), "reader buffer must be drained");
        self.s
    }

    async fn fill(&mut self) -> Result<bool> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut tmp = [0u8; 16384];
        let n = self.s.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    async fn read_line(&mut self, wait: Duration) -> Result<Vec<u8>> {
        loop {
            if let Some(p) = self.remaining().iter().position(|&b| b == b'\n') {
                let line = self.buf[self.pos..self.pos + p + 1].to_vec();
                self.pos += p + 1;
                return Ok(line);
            }
            if self.remaining().len() > MAX_HEAD {
                bail!("header line too long");
            }
            let more = match tokio::time::timeout(wait, self.fill()).await {
                Ok(r) => r?,
                Err(_) => bail!("timed out reading response head"),
            };
            if !more {
                bail!("closed mid-line");
            }
        }
    }

    /// Copy exactly n bytes to the writer, counting them as downstream traffic.
    async fn pipe_to(
        &mut self,
        w: &mut TcpStream,
        mut n: usize,
        stats: &Stats,
        key: u16,
    ) -> Result<()> {
        let take = self.remaining().len().min(n);
        if take > 0 {
            w.write_all(&self.buf[self.pos..self.pos + take]).await?;
            self.pos += take;
            n -= take;
            stats.out_bytes.fetch_add(take as u64, Ordering::Relaxed);
            stats.add(key, 0, take as u64);
        }
        let mut tmp = [0u8; 16384];
        while n > 0 {
            let want = n.min(tmp.len());
            let got = self.s.read(&mut tmp[..want]).await?;
            if got == 0 {
                bail!("closed mid-body");
            }
            w.write_all(&tmp[..got]).await?;
            stats.out_bytes.fetch_add(got as u64, Ordering::Relaxed);
            stats.add(key, 0, got as u64);
            n -= got;
        }
        Ok(())
    }

    async fn pipe_chunked(&mut self, w: &mut TcpStream, stats: &Stats, key: u16) -> Result<()> {
        loop {
            let line = self.read_line(RESPONSE_HEAD_TIMEOUT).await?;
            w.write_all(&line).await?;
            stats.add(key, 0, line.len() as u64);
            let text = String::from_utf8_lossy(&line);
            let size_str = text.trim().split(';').next().unwrap_or("");
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| anyhow!("bad chunk size {:?}", size_str))?;
            if size == 0 {
                // trailers until the blank line
                loop {
                    let l = self.read_line(RESPONSE_HEAD_TIMEOUT).await?;
                    let done = l == b"\r\n" || l == b"\n";
                    w.write_all(&l).await?;
                    stats.add(key, 0, l.len() as u64);
                    if done {
                        break;
                    }
                }
                return Ok(());
            }
            // chunk data + trailing CRLF, copied verbatim
            self.pipe_to(w, size + 2, stats, key).await?;
        }
    }

    async fn flush_to(&mut self, w: &mut TcpStream) -> Result<()> {
        let rest = self.remaining().to_vec();
        self.pos = self.buf.len();
        if !rest.is_empty() {
            w.write_all(&rest).await?;
        }
        Ok(())
    }
}

enum Outcome {
    /// Framed response delivered, connection may carry another request.
    Reuse,
    /// Framed response delivered, connection must close.
    Close,
    /// 101 Switching Protocols: the rest is an opaque bidirectional tunnel.
    Upgrade,
    /// Body ends when the origin closes; relay until EOF.
    CloseDelimited,
}

/// Forward one response (skipping 1xx informational heads).
async fn forward_response(
    client: &mut TcpStream,
    reader: &mut Reader,
    method: &str,
    client_close: bool,
    stats: &Arc<Stats>,
    key: u16,
) -> Result<Outcome> {
    loop {
        let mut raw: Vec<u8> = Vec::new();
        let status_line = reader.read_line(RESPONSE_HEAD_TIMEOUT).await?;
        raw.extend_from_slice(&status_line);
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let line = reader.read_line(RESPONSE_HEAD_TIMEOUT).await?;
            let done = line == b"\r\n" || line == b"\n";
            raw.extend_from_slice(&line);
            if done {
                break;
            }
            let text = String::from_utf8_lossy(&line);
            if let Some((name, value)) = text.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        client.write_all(&raw).await?;
        stats
            .out_bytes
            .fetch_add(raw.len() as u64, Ordering::Relaxed);
        stats.add(key, 0, raw.len() as u64);

        let status: u16 = String::from_utf8_lossy(&status_line)
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("bad status line"))?;

        if status == 101 {
            reader.flush_to(client).await?;
            return Ok(Outcome::Upgrade);
        }
        if status < 200 {
            continue; // informational, the real response follows
        }

        let resp_close = has_token(&headers, "connection", "close")
            || (status_line.starts_with(b"HTTP/1.0")
                && !has_token(&headers, "connection", "keep-alive"));
        let no_body = status == 204 || status == 304 || method.eq_ignore_ascii_case("HEAD");
        let chunked = has_token(&headers, "transfer-encoding", "chunked");
        let content_length =
            header(&headers, "content-length").and_then(|v| v.parse::<usize>().ok());

        if no_body {
            // nothing to copy
        } else if let Some(n) = content_length {
            reader.pipe_to(client, n, stats, key).await?;
        } else if chunked {
            reader.pipe_chunked(client, stats, key).await?;
        } else {
            reader.flush_to(client).await?;
            return Ok(Outcome::CloseDelimited);
        }

        if resp_close || client_close {
            return Ok(Outcome::Close);
        }
        return Ok(Outcome::Reuse);
    }
}

struct PlainReq {
    method: String,
    host: String,
    port: u16,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    has_body: bool,
    client_close: bool,
    leftover: Vec<u8>,
}

fn parse_plain(buf: &[u8], end: usize) -> Result<PlainReq> {
    let (line, headers) = parse_head_lines(&buf[..end]);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
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
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let client_close = has_token(&headers, "connection", "close")
        || (version == "HTTP/1.0" && !has_token(&headers, "connection", "keep-alive"));
    let has_body = header(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .map(|n| n > 0)
        .unwrap_or(false)
        || has_token(&headers, "transfer-encoding", "chunked");
    Ok(PlainReq {
        method,
        host,
        port,
        path,
        version,
        headers,
        has_body,
        client_close,
        leftover: buf[end + 4..].to_vec(),
    })
}

fn build_origin_request(req: &PlainReq, force_close: bool) -> String {
    let mut out = format!("{} {} {}\r\n", req.method, req.path, req.version);
    let connection_tokens: Vec<String> = header(&req.headers, "connection")
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    for (name, value) in &req.headers {
        if HOP_BY_HOP.contains(&name.as_str())
            || name == "connection"
            || connection_tokens.iter().any(|t| t == name)
        {
            continue;
        }
        out.push_str(&format!("{}: {}\r\n", name, value));
    }
    out.push_str(if force_close {
        "Connection: close\r\n"
    } else {
        "Connection: keep-alive\r\n"
    });
    out.push_str("\r\n");
    out
}

/// Absolute-form HTTP session with keep-alive: each request is routed independently,
/// the origin connection is reused while host/port/route stay the same, and responses
/// are framed (Content-Length / chunked / close-delimited) so bodies are never mixed
/// with headers. Requests carrying a body use a single-shot relay with Connection: close.
async fn plain_session(
    mut client: TcpStream,
    first: PlainReq,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
    auth: Option<(String, String)>,
    log_requests: bool,
) -> Result<()> {
    // (host, port, stats key, buffered origin connection)
    let mut current: Option<(String, u16, u16, Reader)> = None;
    let mut req = first;
    loop {
        let decision = routes.read().unwrap().pick(&req.host);
        if log_requests {
            app_log(&format!(
                "http {} {}:{} -> {}",
                req.method,
                req.host,
                req.port,
                describe(decision)
            ));
            log(
                &logs,
                format!(
                    "http {} {}:{} -> {}",
                    req.method,
                    req.host,
                    req.port,
                    describe(decision)
                ),
            );
        }
        if decision == Decision::Blocked {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            log(
                &logs,
                format!(
                    "blocked {}:{} (target profile is not running)",
                    req.host, req.port
                ),
            );
            return Ok(());
        }
        let key = key_of(decision);
        stats.conn(key);
        let need_new = match &current {
            Some((h, p, k, _)) => *h != req.host || *p != req.port || *k != key,
            None => true,
        };
        if need_new {
            let _ = current.take(); // dropping the Reader closes the previous origin connection
            let up = match decision {
                Decision::Via(p) => Some(p),
                _ => None,
            };
            match connect_via(&req.host, req.port, up).await {
                Ok(remote) => {
                    current = Some((
                        req.host.clone(),
                        req.port,
                        key,
                        Reader::new(remote, Vec::new()),
                    ));
                }
                Err(e) => {
                    client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    log(
                        &logs,
                        format!(
                            "http {} {}:{} failed: {}",
                            req.method, req.host, req.port, e
                        ),
                    );
                    return Err(e);
                }
            }
        }
        let (_, _, k, reader) = current.as_mut().unwrap();
        let key = *k;
        // A request with a body (or pipelined trailing bytes) is relayed single-shot:
        // we force Connection: close so framing stays unambiguous.
        let force_close = req.client_close || req.has_body || !req.leftover.is_empty();
        let out = build_origin_request(&req, force_close);
        reader.s.write_all(out.as_bytes()).await?;
        stats
            .in_bytes
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        stats.add(key, out.len() as u64, 0);
        if !req.leftover.is_empty() {
            // Body bytes that arrived together with the head: forward verbatim, NOT as headers.
            reader.s.write_all(&req.leftover).await?;
            stats
                .in_bytes
                .fetch_add(req.leftover.len() as u64, Ordering::Relaxed);
            stats.add(key, req.leftover.len() as u64, 0);
        }
        if force_close {
            let (_, _, _, reader) = current.take().unwrap();
            let remote = reader.into_stream();
            return relay(client, remote, stats, key).await;
        }
        let outcome = forward_response(
            &mut client,
            reader,
            &req.method,
            req.client_close,
            &stats,
            key,
        )
        .await?;
        match outcome {
            Outcome::Close => return Ok(()),
            Outcome::Upgrade | Outcome::CloseDelimited => {
                let (_, _, _, reader) = current.take().unwrap();
                let remote = reader.into_stream();
                return relay(client, remote, stats, key).await;
            }
            Outcome::Reuse => {}
        }
        // Keep-alive: read the next request from the client.
        let (buf, end) = read_head(&mut client, KEEPALIVE_IDLE_TIMEOUT).await?;
        req = parse_plain(&buf, end)?;
        if !http_authorized(&req.headers, &auth) {
            client
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"kubevpn\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            bail!("proxy auth required");
        }
    }
}

async fn handle_http(
    mut s: TcpStream,
    routes: Arc<RwLock<Routes>>,
    stats: Arc<Stats>,
    logs: Logs,
) -> Result<()> {
    let (auth, log_requests) = {
        let r = routes.read().unwrap();
        (r.auth.clone(), r.log_requests)
    };
    let (buf, end) = read_head(&mut s, HANDSHAKE_TIMEOUT).await?;
    let (request_line, headers) = parse_head_lines(&buf[..end]);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if !http_authorized(&headers, &auth) {
        s.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"kubevpn\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
        bail!("proxy auth required");
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target)?;
        let decision = routes.read().unwrap().pick(&host);
        if log_requests {
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
        }
        if decision == Decision::Blocked {
            s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            log(
                &logs,
                format!("blocked {}:{} (target profile is not running)", host, port),
            );
            return Ok(());
        }
        let key = key_of(decision);
        stats.conn(key);
        let up = match decision {
            Decision::Via(p) => Some(p),
            _ => None,
        };
        return match connect_via(&host, port, up).await {
            Ok(mut remote) => {
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let leftover = &buf[end + 4..];
                if !leftover.is_empty() {
                    remote.write_all(leftover).await?;
                }
                relay(s, remote, stats, key).await
            }
            Err(e) => {
                s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                log(
                    &logs,
                    format!("http CONNECT {}:{} failed: {}", host, port, e),
                );
                Err(e)
            }
        };
    }

    let req = parse_plain(&buf, end)?;
    plain_session(s, req, routes, stats, logs, auth, log_requests).await
}

pub async fn serve(
    listener: TcpListener,
    routes: Arc<RwLock<Routes>>,
    logs: Logs,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
) {
    if let Ok(addr) = listener.local_addr() {
        log(&logs, format!("mixed listener on {}", addr));
    }
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
            let res = match tokio::time::timeout(HANDSHAKE_TIMEOUT, sniff_mode(&stream)).await {
                Ok(Ok(Mode::Socks5)) => {
                    handle_socks(stream, routes, stats2.clone(), logs2.clone()).await
                }
                Ok(Ok(Mode::Http)) => {
                    handle_http(stream, routes, stats2.clone(), logs2.clone()).await
                }
                Ok(Ok(Mode::Socks4)) => {
                    let msg = "SOCKS4 is not supported (it resolves DNS locally) - use HTTP proxy or SOCKS5";
                    log(&logs2, msg);
                    app_log(msg);
                    Err(anyhow!("socks4 unsupported"))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow!("closed before first byte (timeout)")),
            };
            if let Err(e) = res {
                let m = e.to_string();
                if !m.contains("closed") && !m.contains("only CONNECT") && !m.contains("timed out")
                {
                    log(&logs2, format!("error: {}", m));
                }
            }
            stats2.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    log(&logs, "listener stopped");
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
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
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
            serve(listener, routes, logs, stats, stop).await;
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
        Routes::build(
            rules.into_iter().map(|(s, p)| (s.to_string(), p)).collect(),
            default,
            configured,
            fail_closed,
            None,
            true,
        )
    }

    #[test]
    fn matches_exact_and_subdomain() {
        let r = table(vec![("example.com", Some(15001))], None, false, false);
        assert_eq!(r.pick("example.com"), Decision::Via(15001));
        assert_eq!(r.pick("api.example.com"), Decision::Via(15001));
        assert_eq!(r.pick("EXAMPLE.COM"), Decision::Via(15001));
        assert_eq!(r.pick("example.com."), Decision::Via(15001));
    }

    #[test]
    fn does_not_match_lookalike_domain() {
        let r = table(vec![("example.com", Some(15001))], None, false, false);
        assert_eq!(r.pick("notexample.com"), Decision::Direct);
        assert_eq!(r.pick("example.com.evil.net"), Decision::Direct);
    }

    #[test]
    fn longest_suffix_wins_regardless_of_order() {
        let r = table(
            vec![("gbinfra.io", Some(15002)), ("k8s.gbinfra.io", Some(15009))],
            None,
            false,
            false,
        );
        assert_eq!(r.pick("k8s.gbinfra.io"), Decision::Via(15009));
        assert_eq!(r.pick("auth.gbinfra.io"), Decision::Via(15002));
        let r2 = table(
            vec![("k8s.gbinfra.io", Some(15009)), ("gbinfra.io", Some(15002))],
            None,
            false,
            false,
        );
        assert_eq!(r2.pick("k8s.gbinfra.io"), Decision::Via(15009));
    }

    #[test]
    fn ipv4_cidr_rules() {
        let r = table(
            vec![("10.0.0.0/8", Some(15001)), ("10.1.0.0/16", Some(15002))],
            None,
            false,
            false,
        );
        assert_eq!(r.pick("10.2.3.4"), Decision::Via(15001));
        assert_eq!(r.pick("10.1.2.3"), Decision::Via(15002));
        assert_eq!(r.pick("11.0.0.1"), Decision::Direct);
        // an IP must not match a domain rule
        let r2 = table(vec![("example.com", Some(15001))], None, false, false);
        assert_eq!(r2.pick("10.0.0.1"), Decision::Direct);
    }

    #[test]
    fn bare_ip_and_ipv6_cidr_rules() {
        let r = table(
            vec![("192.168.1.5", Some(15001)), ("2001:db8::/32", Some(15002))],
            None,
            false,
            false,
        );
        assert_eq!(r.pick("192.168.1.5"), Decision::Via(15001));
        assert_eq!(r.pick("192.168.1.6"), Decision::Direct);
        assert_eq!(r.pick("2001:db8::1"), Decision::Via(15002));
        assert_eq!(r.pick("2001:db9::1"), Decision::Direct);
        // a domain must not match an IP rule
        assert_eq!(r.pick("example.com"), Decision::Direct);
    }

    #[test]
    fn invalid_rules_are_dropped() {
        let r = table(
            vec![
                ("10.0.0.0/33", Some(15001)),
                ("example.com/24", Some(15002)),
                ("", Some(15003)),
            ],
            None,
            false,
            false,
        );
        assert_eq!(r.pick("10.0.0.1"), Decision::Direct);
        assert_eq!(r.pick("example.com"), Decision::Direct);
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

    #[test]
    fn basic_auth_check() {
        let auth = Some(("user".to_string(), "pass".to_string()));
        let ok = vec![(
            "proxy-authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        )];
        let bad = vec![(
            "proxy-authorization".to_string(),
            "Basic d3Jvbmc=".to_string(),
        )];
        assert!(http_authorized(&ok, &auth));
        assert!(!http_authorized(&bad, &auth));
        assert!(!http_authorized(&[], &auth));
        assert!(http_authorized(&[], &None));
    }

    #[test]
    fn origin_request_strips_hop_by_hop_and_keeps_body_headers() {
        let req = PlainReq {
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/x".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("host".to_string(), "example.com".to_string()),
                ("content-length".to_string(), "5".to_string()),
                ("proxy-connection".to_string(), "keep-alive".to_string()),
                ("connection".to_string(), "keep-alive, X-Custom".to_string()),
                ("x-custom".to_string(), "1".to_string()),
            ],
            has_body: true,
            client_close: false,
            leftover: vec![],
        };
        let out = build_origin_request(&req, true);
        assert!(out.starts_with("POST /x HTTP/1.1\r\n"));
        assert!(out.contains("content-length: 5\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.contains("proxy-connection"));
        assert!(!out.contains("x-custom"));
        assert!(!out.contains("keep-alive, X-Custom"));
    }
}

/// Integration tests for the mixed port. Everything binds 127.0.0.1:0 (ephemeral
/// ports); the real listener on 3080 and any running sidecars are never touched.
/// log_requests is off so tests do not write into the diagnostic app log.
#[cfg(test)]
mod integration {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn test_routes(
        rules: Vec<(&str, Option<u16>)>,
        default: Option<u16>,
        fail_closed: bool,
    ) -> Routes {
        Routes::build(
            rules.into_iter().map(|(s, p)| (s.to_string(), p)).collect(),
            default,
            default.is_some(),
            fail_closed,
            None,
            false,
        )
    }

    async fn start_proxy(routes: Routes) -> (u16, Arc<Stats>) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let logs = crate::util::new_logs();
        tokio::spawn(serve(
            listener,
            Arc::new(RwLock::new(routes)),
            logs,
            stats.clone(),
            stop,
        ));
        (port, stats)
    }

    /// A fake profile sidecar: SOCKS5 server that answers CONNECT with success,
    /// sends a marker so tests can tell upstreams apart, then echoes bytes.
    async fn fake_upstream(marker: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    if s.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut head = [0u8; 4];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let skip = match head[3] {
                        0x01 => 4,
                        0x03 => {
                            let mut l = [0u8; 1];
                            if s.read_exact(&mut l).await.is_err() {
                                return;
                            }
                            l[0] as usize
                        }
                        0x04 => 16,
                        _ => return,
                    };
                    let mut rest = vec![0u8; skip + 2];
                    if s.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    let _ = s.write_all(marker.as_bytes()).await;
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    async fn socks_connect(proxy: u16, host: &str, port: u16) -> TcpStream {
        let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [0x05, 0x00]);
        let hb = host.as_bytes();
        let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(head[1], 0x00, "connect refused");
        let skip = match head[3] {
            0x01 => 4,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                l[0] as usize
            }
            0x04 => 16,
            _ => panic!("bad atyp"),
        };
        let mut rest = vec![0u8; skip + 2];
        s.read_exact(&mut rest).await.unwrap();
        s
    }

    /// Read until \r\n\r\n; returns the WHOLE buffer (head + any bytes that arrived
    /// with it) and the terminator offset, so callers never lose body bytes.
    async fn read_head_test(s: &mut TcpStream) -> (Vec<u8>, usize) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = s.read(&mut tmp).await.unwrap();
            assert!(n > 0, "closed while reading head");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return (buf, p);
            }
        }
    }

    /// Collect exactly n bytes starting from already-read leftover bytes.
    async fn take_bytes(s: &mut TcpStream, leftover: &[u8], n: usize) -> Vec<u8> {
        let mut out = leftover.to_vec();
        while out.len() < n {
            let mut tmp = [0u8; 1024];
            let got = s.read(&mut tmp).await.unwrap();
            assert!(got > 0, "closed while reading body");
            out.extend_from_slice(&tmp[..got]);
        }
        out.truncate(n);
        out
    }

    /// Every test is bounded so a logic error fails fast instead of hanging the suite.
    async fn bounded<F: std::future::Future<Output = ()>>(f: F) {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test timed out after 10s");
    }

    #[tokio::test]
    async fn socks5_connect_via_upstream() {
        bounded(async {
            let up = fake_upstream("UP-A").await;
            let (proxy, stats) =
                start_proxy(test_routes(vec![("example.test", Some(up))], None, false)).await;
            let mut s = socks_connect(proxy, "example.test", 443).await;
            let mut marker = [0u8; 4];
            s.read_exact(&mut marker).await.unwrap();
            assert_eq!(&marker, b"UP-A");
            s.write_all(b"ping").await.unwrap();
            let mut echo = [0u8; 4];
            s.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"ping");
            assert_eq!(stats.port_snapshot(up).conns, 1);
            assert!(stats.port_snapshot(up).in_bytes >= 4);
        })
        .await;
    }

    #[tokio::test]
    async fn socks5_connect_direct() {
        bounded(async {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = echo.accept().await.unwrap();
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
            });
            let (proxy, stats) = start_proxy(test_routes(vec![], None, false)).await;
            let mut s = socks_connect(proxy, "127.0.0.1", echo_port).await;
            s.write_all(b"direct").await.unwrap();
            let mut buf = [0u8; 6];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"direct");
            assert_eq!(stats.port_snapshot(0).conns, 1);
        })
        .await;
    }

    #[tokio::test]
    async fn longest_match_end_to_end() {
        bounded(async {
            let a = fake_upstream("AAA").await;
            let b = fake_upstream("BBB").await;
            let (proxy, _) = start_proxy(test_routes(
                vec![("example.test", Some(a)), ("sub.example.test", Some(b))],
                None,
                false,
            ))
            .await;
            let mut s = socks_connect(proxy, "sub.example.test", 443).await;
            let mut m = [0u8; 3];
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(&m, b"BBB");
            let mut s2 = socks_connect(proxy, "example.test", 443).await;
            s2.read_exact(&mut m).await.unwrap();
            assert_eq!(&m, b"AAA");
        })
        .await;
    }

    #[tokio::test]
    async fn http_connect_via_upstream() {
        bounded(async {
            let up = fake_upstream("UP-H").await;
            let (proxy, _) =
                start_proxy(test_routes(vec![("example.test", Some(up))], None, false)).await;
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .await
                .unwrap();
            let (buf, end) = read_head_test(&mut s).await;
            assert!(String::from_utf8_lossy(&buf[..end]).starts_with("HTTP/1.1 200"));
            let marker = take_bytes(&mut s, &buf[end + 4..], 4).await;
            assert_eq!(&marker, b"UP-H");
            s.write_all(b"xyz").await.unwrap();
            let mut echo = [0u8; 3];
            s.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"xyz");
        })
        .await;
    }

    #[tokio::test]
    async fn http_absolute_get_keepalive_two_requests() {
        bounded(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                // first request
                let (buf, end) = read_head_test(&mut s).await;
                let text = String::from_utf8_lossy(&buf[..end]).to_string();
                assert!(text.starts_with("GET /path HTTP/1.1\r\n"), "got: {}", text);
                assert!(!text.contains("http://"));
                assert!(text.to_ascii_lowercase().contains("connection: keep-alive"));
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
                )
                .await
                .unwrap();
                // second request on the SAME origin connection (reused by the proxy)
                let (buf2, end2) = read_head_test(&mut s).await;
                let text2 = String::from_utf8_lossy(&buf2[..end2]).to_string();
                assert!(
                    text2.starts_with("GET /second HTTP/1.1\r\n"),
                    "got: {}",
                    text2
                );
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld",
                )
                .await
                .unwrap();
            });
            let (proxy, _) = start_proxy(test_routes(vec![], None, false)).await;
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            let req1 = format!(
                "GET http://127.0.0.1:{}/path HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                origin_port, origin_port
            );
            s.write_all(req1.as_bytes()).await.unwrap();
            let (buf, end) = read_head_test(&mut s).await;
            assert!(String::from_utf8_lossy(&buf[..end]).starts_with("HTTP/1.1 200"));
            let body = take_bytes(&mut s, &buf[end + 4..], 5).await;
            assert_eq!(&body, b"hello");
            // keep-alive: second request on the same client connection
            let req2 = format!(
                "GET http://127.0.0.1:{}/second HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                origin_port, origin_port
            );
            s.write_all(req2.as_bytes()).await.unwrap();
            let (buf2, end2) = read_head_test(&mut s).await;
            assert!(String::from_utf8_lossy(&buf2[..end2]).starts_with("HTTP/1.1 200"));
            let body2 = take_bytes(&mut s, &buf2[end2 + 4..], 5).await;
            assert_eq!(&body2, b"world");
        })
        .await;
    }

    #[tokio::test]
    async fn http_post_body_arriving_with_head_is_not_mangled() {
        bounded(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let (buf, end) = read_head_test(&mut s).await;
                let text = String::from_utf8_lossy(&buf[..end]).to_string();
                assert!(text.starts_with("POST /submit HTTP/1.1\r\n"), "got: {}", text);
                assert!(text.to_ascii_lowercase().contains("content-length: 11"));
                assert!(text.to_ascii_lowercase().contains("connection: close"));
                let body = take_bytes(&mut s, &buf[end + 4..], 11).await;
                assert_eq!(&body, b"hello world");
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await
                    .unwrap();
            });
            let (proxy, _) = start_proxy(test_routes(vec![], None, false)).await;
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            // head and body in ONE write: the old code treated body bytes as headers
            let req = format!(
                "POST http://127.0.0.1:{}/submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
                origin_port
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let (buf, end) = read_head_test(&mut s).await;
            assert!(String::from_utf8_lossy(&buf[..end]).starts_with("HTTP/1.1 200"));
            let body = take_bytes(&mut s, &buf[end + 4..], 2).await;
            assert_eq!(&body, b"ok");
        })
        .await;
    }

    #[tokio::test]
    async fn http_chunked_response_is_forwarded_verbatim() {
        bounded(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let _ = read_head_test(&mut s).await;
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            });
            let (proxy, _) = start_proxy(test_routes(vec![], None, false)).await;
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            let req = format!(
                "GET http://127.0.0.1:{}/c HTTP/1.1\r\nHost: x\r\n\r\n",
                origin_port
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut all = Vec::new();
            s.read_to_end(&mut all).await.unwrap();
            let text = String::from_utf8_lossy(&all);
            assert!(text.contains("5\r\nhello\r\n"));
            assert!(text.contains("6\r\n world\r\n"));
            assert!(text.ends_with("0\r\n\r\n"));
        })
        .await;
    }

    #[tokio::test]
    async fn blocked_targets_refuse_traffic() {
        bounded(async {
            let (proxy, _) =
                start_proxy(test_routes(vec![("example.test", None)], None, true)).await;
            // SOCKS5: general failure reply
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            s.read_exact(&mut m).await.unwrap();
            let hb = b"example.test";
            let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
            req.extend_from_slice(hb);
            req.extend_from_slice(&443u16.to_be_bytes());
            s.write_all(&req).await.unwrap();
            let mut reply = [0u8; 10];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0x01);
            // HTTP CONNECT: 502
            let mut h = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            h.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let (buf, end) = read_head_test(&mut h).await;
            assert!(String::from_utf8_lossy(&buf[..end]).starts_with("HTTP/1.1 502"));
        })
        .await;
    }

    #[tokio::test]
    async fn socks_method_negotiation_rejects_unoffered_method() {
        bounded(async {
            let (proxy, _) = start_proxy(test_routes(vec![], None, false)).await;
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            // client offers only username/password, server wants no-auth
            s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut m = [0u8; 2];
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0xff]);
        })
        .await;
    }

    #[tokio::test]
    async fn socks_rfc1929_auth() {
        bounded(async {
            let up = fake_upstream("AUTH").await;
            let mut routes = test_routes(vec![("example.test", Some(up))], None, false);
            routes.auth = Some(("u".to_string(), "p".to_string()));
            let (proxy, _) = start_proxy(routes).await;
            // no-auth only -> rejected
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0xff]);
            // wrong password -> auth failure
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x02]);
            s.write_all(&[0x01, 0x01, b'u', 0x01, b'x']).await.unwrap();
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await.unwrap();
            assert_eq!(ar, [0x01, 0x01]);
            // correct credentials -> CONNECT works
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x02]);
            s.write_all(&[0x01, 0x01, b'u', 0x01, b'p']).await.unwrap();
            s.read_exact(&mut ar).await.unwrap();
            assert_eq!(ar, [0x01, 0x00]);
            let hb = b"example.test";
            let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
            req.extend_from_slice(hb);
            req.extend_from_slice(&443u16.to_be_bytes());
            s.write_all(&req).await.unwrap();
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], 0);
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.unwrap();
            let mut marker = [0u8; 4];
            s.read_exact(&mut marker).await.unwrap();
            assert_eq!(&marker, b"AUTH");
        })
        .await;
    }

    #[tokio::test]
    async fn http_basic_proxy_auth() {
        bounded(async {
            let up = fake_upstream("HAUTH").await;
            let mut routes = test_routes(vec![("example.test", Some(up))], None, false);
            routes.auth = Some(("u".to_string(), "p".to_string()));
            let (proxy, _) = start_proxy(routes).await;
            // without credentials -> 407
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let (buf, end) = read_head_test(&mut s).await;
            let text = String::from_utf8_lossy(&buf[..end]).to_string();
            assert!(text.starts_with("HTTP/1.1 407"), "got: {}", text);
            assert!(text.contains("Proxy-Authenticate: Basic"));
            // with credentials -> tunnel established
            let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            s.write_all(
                b"CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
            )
            .await
            .unwrap();
            let (buf, end) = read_head_test(&mut s).await;
            assert!(String::from_utf8_lossy(&buf[..end]).starts_with("HTTP/1.1 200"));
            let marker = take_bytes(&mut s, &buf[end + 4..], 5).await;
            assert_eq!(&marker, b"HAUTH");
        })
        .await;
    }

    #[tokio::test]
    async fn udp_associate_routes_through_upstream() {
        bounded(async {
            // Fake sidecar with a SOCKS5 UDP relay that reflects datagrams.
            let ctl = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let up_port = ctl.local_addr().unwrap().port();
            let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let udp_addr = udp.local_addr().unwrap();
            {
                let udp = udp.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    while let Ok((n, src)) = udp.recv_from(&mut buf).await {
                        let _ = udp.send_to(&buf[..n], src).await;
                    }
                });
            }
            tokio::spawn(async move {
                while let Ok((mut s, _)) = ctl.accept().await {
                    let udp_addr = udp_addr;
                    tokio::spawn(async move {
                        let mut g = [0u8; 3];
                        if s.read_exact(&mut g).await.is_err() {
                            return;
                        }
                        let _ = s.write_all(&[0x05, 0x00]).await;
                        let mut head = [0u8; 4];
                        if s.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let mut rest = [0u8; 6];
                        if s.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        if head[1] == 0x03 {
                            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                            reply.extend_from_slice(&[127, 0, 0, 1]);
                            reply.extend_from_slice(&udp_addr.port().to_be_bytes());
                            let _ = s.write_all(&reply).await;
                            // keep the control connection open
                            let mut sink = [0u8; 1];
                            loop {
                                match s.read(&mut sink).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {}
                                }
                            }
                        }
                    });
                }
            });

            let (proxy, _) = start_proxy(test_routes(
                vec![("example.test", Some(up_port))],
                None,
                false,
            ))
            .await;
            let mut ctl_s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
            ctl_s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl_s.read_exact(&mut m).await.unwrap();
            // UDP ASSOCIATE with 0.0.0.0:0
            ctl_s
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut head = [0u8; 4];
            ctl_s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], 0);
            let mut addr = [0u8; 6];
            ctl_s.read_exact(&mut addr).await.unwrap();
            let relay_port = u16::from_be_bytes([addr[4], addr[5]]);
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let pkt = build_udp_header("example.test", 9999, b"udp-ping");
            client
                .send_to(&pkt, ("127.0.0.1", relay_port))
                .await
                .unwrap();
            let mut buf = vec![0u8; 65535];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .expect("udp echo timed out")
                .unwrap();
            let (host, port, payload) = parse_udp_header(&buf[..n]).unwrap();
            assert_eq!(host, "example.test");
            assert_eq!(port, 9999);
            assert_eq!(payload, b"udp-ping");
        })
        .await;
    }
}
