//! Conversion of share-URI subscription payloads (vless://, vmess://, trojan://, ss://,
//! optionally base64-encoded) into Xray-compatible JSON configs.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::subs::Item;
use crate::util::{b64_decode, percent_decode};

/// Accepts a plain list of URIs or a base64 blob of such a list (the format most
/// subscription panels serve when they do not serve JSON).
pub fn parse_uri_list(body: &str) -> Result<Vec<Item>> {
    let text = if body.contains("://") {
        body.to_string()
    } else {
        let bytes = b64_decode(body).ok_or_else(|| anyhow!("not a URI list or base64"))?;
        String::from_utf8(bytes).map_err(|_| anyhow!("base64 payload is not UTF-8"))?
    };
    // Some panels base64-encode a JSON payload; hand it back to the JSON parser.
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        return crate::subs::parse(&text);
    }
    // A WireGuard INI hiding in a base64 subscription is a valid single profile.
    if text.contains("[Interface]") && text.contains("[Peer]") {
        return Ok(vec![Item {
            name: None,
            text: text.trim().to_string(),
        }]);
    }
    let mut out = Vec::new();
    let mut unsupported = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((scheme, rest)) = line.split_once("://") else {
            continue;
        };
        let converted = match scheme.to_ascii_lowercase().as_str() {
            "vless" => vless_config(rest),
            "vmess" => vmess_config(rest),
            "trojan" => trojan_config(rest),
            "ss" => ss_config(rest),
            _ => {
                unsupported += 1;
                continue;
            }
        };
        match converted {
            Ok(v) => {
                let name = v
                    .get("remarks")
                    .and_then(|r| r.as_str())
                    .map(|s| s.to_string());
                out.push(Item {
                    name,
                    text: v.to_string(),
                });
            }
            Err(_) => unsupported += 1,
        }
    }
    if out.is_empty() {
        bail!(
            "no supported configs in the payload ({} unsupported entries; supported: vless, vmess, trojan, ss)",
            unsupported
        );
    }
    Ok(out)
}

struct Parts {
    userinfo: Option<String>,
    host: String,
    port: u16,
    params: HashMap<String, String>,
    name: Option<String>,
}

fn split_parts(rest: &str, default_port: u16) -> Result<Parts> {
    let (main, fragment) = match rest.split_once('#') {
        Some((m, f)) => (m, Some(f)),
        None => (rest, None),
    };
    let (authority, query) = match main.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (main, None),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(percent_decode(u)), h),
        None => (None, authority),
    };
    let (host, port) = split_hostport(hostport, default_port)?;
    let mut params = HashMap::new();
    if let Some(q) = query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            params.insert(percent_decode(k), percent_decode(v));
        }
    }
    let name = fragment
        .map(percent_decode)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(Parts {
        userinfo,
        host,
        port,
        params,
        name,
    })
}

fn split_hostport(s: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("bad ipv6 host"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>()?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse::<u16>()?)),
        None => Ok((s.to_string(), default_port)),
    }
}

fn param<'a>(p: &'a Parts, key: &str) -> Option<&'a str> {
    p.params
        .get(key)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
}

/// Build streamSettings shared by vless/trojan (and partly vmess).
fn stream_settings(p: &Parts, default_security: &str) -> Value {
    let network = param(p, "type").unwrap_or("tcp");
    let security = param(p, "security").unwrap_or(default_security);
    let sni = param(p, "sni").unwrap_or(&p.host);
    let mut stream = json!({ "network": network, "security": security });
    match security {
        "tls" => {
            let mut tls = json!({ "serverName": sni });
            if let Some(fp) = param(p, "fp") {
                tls["fingerprint"] = json!(fp);
            }
            if let Some(alpn) = param(p, "alpn") {
                tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
            }
            stream["tlsSettings"] = tls;
        }
        "reality" => {
            stream["realitySettings"] = json!({
                "serverName": sni,
                "fingerprint": param(p, "fp").unwrap_or("chrome"),
                "publicKey": param(p, "pbk").unwrap_or(""),
                "shortId": param(p, "sid").unwrap_or(""),
                "spiderX": param(p, "spx").unwrap_or(""),
            });
        }
        _ => {}
    }
    let ws_host = param(p, "host").unwrap_or(&p.host);
    match network {
        "ws" => {
            stream["wsSettings"] = json!({
                "path": param(p, "path").unwrap_or("/"),
                "headers": { "Host": ws_host },
            });
        }
        "grpc" => {
            stream["grpcSettings"] = json!({
                "serviceName": param(p, "serviceName").unwrap_or(""),
            });
        }
        "httpupgrade" => {
            stream["httpupgradeSettings"] = json!({
                "path": param(p, "path").unwrap_or("/"),
                "host": ws_host,
            });
        }
        "tcp" if param(p, "headerType") == Some("http") => {
            stream["tcpSettings"] = json!({
                "header": {
                    "type": "http",
                    "request": {
                        "path": [param(p, "path").unwrap_or("/")],
                        "headers": { "Host": [ws_host] },
                    },
                },
            });
        }
        _ => {}
    }
    stream
}

fn vless_config(rest: &str) -> Result<Value> {
    let p = split_parts(rest, 443)?;
    let uuid = p
        .userinfo
        .clone()
        .ok_or_else(|| anyhow!("vless: missing uuid"))?;
    let mut user = json!({
        "id": uuid,
        "encryption": param(&p, "encryption").unwrap_or("none"),
    });
    if let Some(flow) = param(&p, "flow") {
        user["flow"] = json!(flow);
    }
    Ok(json!({
        "remarks": p.name,
        "outbounds": [{
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": p.host,
                    "port": p.port,
                    "users": [user],
                }],
            },
            "streamSettings": stream_settings(&p, "none"),
        }],
    }))
}

fn vmess_config(rest: &str) -> Result<Value> {
    // vmess://base64(json) — the fragment name lives inside the JSON as "ps".
    let main = rest.split_once('#').map(|(m, _)| m).unwrap_or(rest);
    let bytes = b64_decode(main).ok_or_else(|| anyhow!("vmess: bad base64"))?;
    let v: Value = serde_json::from_slice(&bytes)?;
    let get_str = |k: &str| -> Option<String> {
        v.get(k).and_then(|x| match x {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    };
    let host = get_str("add").ok_or_else(|| anyhow!("vmess: missing add"))?;
    let port: u16 = get_str("port")
        .ok_or_else(|| anyhow!("vmess: missing port"))?
        .parse()?;
    let id = get_str("id").ok_or_else(|| anyhow!("vmess: missing id"))?;
    let aid: u64 = get_str("aid").and_then(|s| s.parse().ok()).unwrap_or(0);
    let network = get_str("net").unwrap_or_else(|| "tcp".to_string());
    let tls = get_str("tls").map(|t| t == "tls").unwrap_or(false);
    let sni = get_str("sni").unwrap_or_else(|| host.clone());
    let mut stream = json!({
        "network": network,
        "security": if tls { "tls" } else { "none" },
    });
    if tls {
        let mut tls_settings = json!({ "serverName": sni });
        if let Some(fp) = get_str("fp") {
            tls_settings["fingerprint"] = json!(fp);
        }
        if let Some(alpn) = get_str("alpn") {
            tls_settings["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
        stream["tlsSettings"] = tls_settings;
    }
    let ws_host = get_str("host").unwrap_or_else(|| host.clone());
    match network.as_str() {
        "ws" => {
            stream["wsSettings"] = json!({
                "path": get_str("path").unwrap_or_else(|| "/".to_string()),
                "headers": { "Host": ws_host },
            });
        }
        "grpc" => {
            stream["grpcSettings"] = json!({
                "serviceName": get_str("path").unwrap_or_default(),
            });
        }
        "tcp" if get_str("type").as_deref() == Some("http") => {
            stream["tcpSettings"] = json!({
                "header": {
                    "type": "http",
                    "request": {
                        "path": [get_str("path").unwrap_or_else(|| "/".to_string())],
                        "headers": { "Host": [ws_host] },
                    },
                },
            });
        }
        _ => {}
    }
    Ok(json!({
        "remarks": get_str("ps"),
        "outbounds": [{
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": id,
                        "alterId": aid,
                        "security": get_str("scy").unwrap_or_else(|| "auto".to_string()),
                    }],
                }],
            },
            "streamSettings": stream,
        }],
    }))
}

fn trojan_config(rest: &str) -> Result<Value> {
    let p = split_parts(rest, 443)?;
    let password = p
        .userinfo
        .clone()
        .ok_or_else(|| anyhow!("trojan: missing password"))?;
    Ok(json!({
        "remarks": p.name,
        "outbounds": [{
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "servers": [{
                    "address": p.host,
                    "port": p.port,
                    "password": password,
                }],
            },
            "streamSettings": stream_settings(&p, "tls"),
        }],
    }))
}

fn ss_config(rest: &str) -> Result<Value> {
    let main = rest.split_once('#').map(|(m, _)| m).unwrap_or(rest);
    let main = main.split_once('?').map(|(m, _)| m).unwrap_or(main);
    let (method, password, host, port) = if let Some((userinfo, hostport)) = main.rsplit_once('@') {
        // SIP002: ss://base64(method:password)@host:port
        let decoded = if userinfo.contains(':') {
            percent_decode(userinfo)
        } else {
            String::from_utf8(
                b64_decode(userinfo).ok_or_else(|| anyhow!("ss: bad base64 userinfo"))?,
            )?
        };
        let (m, pw) = decoded
            .split_once(':')
            .ok_or_else(|| anyhow!("ss: bad userinfo"))?;
        let (h, p) = split_hostport(hostport, 8388)?;
        (m.to_string(), pw.to_string(), h, p)
    } else {
        // legacy: ss://base64(method:password@host:port)
        let decoded =
            String::from_utf8(b64_decode(main).ok_or_else(|| anyhow!("ss: bad base64"))?)?;
        let (userinfo, hostport) = decoded
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("ss: bad legacy payload"))?;
        let (m, pw) = userinfo
            .split_once(':')
            .ok_or_else(|| anyhow!("ss: bad userinfo"))?;
        let (h, p) = split_hostport(hostport, 8388)?;
        (m.to_string(), pw.to_string(), h, p)
    };
    let name = rest
        .split_once('#')
        .map(|(_, f)| percent_decode(f))
        .filter(|s| !s.trim().is_empty());
    Ok(json!({
        "remarks": name,
        "outbounds": [{
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }],
            },
        }],
    }))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_reality_uri() {
        let uri = "vless://uuid-123@example.com:443?type=tcp&security=reality&pbk=PUBKEY&sid=ab12&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20NL";
        let items = parse_uri_list(uri).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name.as_deref(), Some("🇳🇱 NL"));
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        let ob = &v["outbounds"][0];
        assert_eq!(ob["protocol"], "vless");
        assert_eq!(ob["settings"]["vnext"][0]["address"], "example.com");
        assert_eq!(ob["settings"]["vnext"][0]["port"], 443);
        assert_eq!(
            ob["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(ob["streamSettings"]["security"], "reality");
        assert_eq!(
            ob["streamSettings"]["realitySettings"]["publicKey"],
            "PUBKEY"
        );
        assert_eq!(ob["streamSettings"]["realitySettings"]["shortId"], "ab12");
        assert_eq!(
            ob["streamSettings"]["realitySettings"]["serverName"],
            "www.microsoft.com"
        );
    }

    #[test]
    fn vless_ws_tls_uri() {
        let uri = "vless://u@host.net:8443?type=ws&security=tls&path=%2Fws&host=cdn.host.net&sni=cdn.host.net&alpn=h2,http/1.1#node";
        let items = parse_uri_list(uri).unwrap();
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        let ss = &v["outbounds"][0]["streamSettings"];
        assert_eq!(ss["network"], "ws");
        assert_eq!(ss["wsSettings"]["path"], "/ws");
        assert_eq!(ss["wsSettings"]["headers"]["Host"], "cdn.host.net");
        assert_eq!(ss["tlsSettings"]["alpn"][0], "h2");
    }

    #[test]
    fn vmess_uri() {
        let payload = r#"{"v":"2","ps":"VM","add":"1.2.3.4","port":"443","id":"uuid","aid":"0","scy":"auto","net":"ws","host":"h.example","path":"/p","tls":"tls","sni":"s.example"}"#;
        let mut b64 = String::new();
        // simple standard base64 encode for the test
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = payload.as_bytes();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            b64.push(T[(n >> 18) as usize & 63] as char);
            b64.push(T[(n >> 12) as usize & 63] as char);
            b64.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            b64.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        let items = parse_uri_list(&format!("vmess://{}", b64)).unwrap();
        assert_eq!(items[0].name.as_deref(), Some("VM"));
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        let ob = &v["outbounds"][0];
        assert_eq!(ob["protocol"], "vmess");
        assert_eq!(ob["settings"]["vnext"][0]["address"], "1.2.3.4");
        assert_eq!(ob["streamSettings"]["wsSettings"]["path"], "/p");
        assert_eq!(
            ob["streamSettings"]["tlsSettings"]["serverName"],
            "s.example"
        );
    }

    #[test]
    fn trojan_uri() {
        let items =
            parse_uri_list("trojan://pw@t.example:443?sni=t.example&type=grpc&serviceName=g#TR")
                .unwrap();
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        let ob = &v["outbounds"][0];
        assert_eq!(ob["protocol"], "trojan");
        assert_eq!(ob["settings"]["servers"][0]["password"], "pw");
        assert_eq!(ob["streamSettings"]["security"], "tls");
        assert_eq!(ob["streamSettings"]["grpcSettings"]["serviceName"], "g");
    }

    #[test]
    fn shadowsocks_both_forms() {
        // SIP002: base64(method:password)@host:port
        let items = parse_uri_list("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#SS").unwrap();
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        let srv = &v["outbounds"][0]["settings"]["servers"][0];
        assert_eq!(srv["method"], "aes-256-gcm");
        assert_eq!(srv["password"], "pass");
        assert_eq!(srv["address"], "1.2.3.4");
        assert_eq!(srv["port"], 8388);
        // legacy: base64(method:password@host:port)
        let legacy = "YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg=";
        let items = parse_uri_list(&format!("ss://{}#L", legacy)).unwrap();
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        assert_eq!(
            v["outbounds"][0]["settings"]["servers"][0]["method"],
            "aes-256-gcm"
        );
        assert_eq!(items[0].name.as_deref(), Some("L"));
    }

    #[test]
    fn base64_list_and_unsupported() {
        // base64 of two lines: one vless, one hysteria2 (unsupported)
        let plain = "vless://u@h:443#A\nhysteria2://pw@h:443#B\n";
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in plain.as_bytes().chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            b64.push(T[(n >> 18) as usize & 63] as char);
            b64.push(T[(n >> 12) as usize & 63] as char);
            b64.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            b64.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        let items = parse_uri_list(&b64).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name.as_deref(), Some("A"));
        assert!(parse_uri_list("hysteria2://x@y:1#z").is_err());
        assert!(parse_uri_list("garbage !!!").is_err());
    }

    #[test]
    fn ipv6_host_in_uri() {
        let items = parse_uri_list("vless://u@[2001:db8::1]:443#V6").unwrap();
        let v: Value = serde_json::from_str(&items[0].text).unwrap();
        assert_eq!(
            v["outbounds"][0]["settings"]["vnext"][0]["address"],
            "2001:db8::1"
        );
    }
}
