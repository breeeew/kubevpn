use anyhow::{bail, Result};

use crate::util::{app_log, proxy_from_env, Logs};

#[derive(Clone, Debug)]
pub struct Item {
    pub name: Option<String>,
    pub text: String,
}

/// Fetches a subscription. The v2rayNG user agent is what makes most servers answer with
/// plain JSON instead of a base64 blob or a clash config.
pub fn fetch(url: &str, _logs: &Logs) -> Result<String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("v2rayNG/1.9.16");
    if let Some(p) = proxy_from_env() {
        if let Ok(proxy) = ureq::Proxy::new(&p) {
            builder = builder.proxy(proxy);
        }
    }
    let body = builder.build().get(url).call()?.into_string()?;
    app_log(&format!(
        "subscription: fetched {} bytes from {}",
        body.len(),
        url
    ));
    Ok(body)
}

fn name_of(item: &serde_json::Value) -> Option<String> {
    item.get("remarks")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Accepts the JSON array of configs that most subscriptions return, or a single config.
pub fn parse(body: &str) -> Result<Vec<Item>> {
    let t = body.trim();
    if t.is_empty() {
        bail!("the server returned an empty body");
    }
    if t.starts_with('[') {
        let items: Vec<serde_json::Value> = serde_json::from_str(t)?;
        let mut out = Vec::new();
        for item in items {
            if item.get("outbounds").is_none() {
                continue;
            }
            out.push(Item {
                name: name_of(&item),
                text: item.to_string(),
            });
        }
        if out.is_empty() {
            bail!("the response contains no tunnel configs");
        }
        return Ok(out);
    }
    if t.starts_with('{') {
        let item: serde_json::Value = serde_json::from_str(t)?;
        if item.get("outbounds").is_none() {
            bail!("the response is not a tunnel config");
        }
        return Ok(vec![Item {
            name: name_of(&item),
            text: item.to_string(),
        }]);
    }
    bail!("unrecognised subscription format (expected JSON)")
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_array_of_configs() {
        let body = r#"[{"remarks":"NL","outbounds":[{"protocol":"vless"}]},{"outbounds":[{"protocol":"vmess"}]}]"#;
        let items = parse(body).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name.as_deref(), Some("NL"));
        assert_eq!(items[1].name, None);
    }

    #[test]
    fn parses_a_single_config() {
        let body = r#"{"remarks":"one","outbounds":[{"protocol":"vless"}]}"#;
        let items = parse(body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name.as_deref(), Some("one"));
    }

    #[test]
    fn skips_entries_without_outbounds() {
        let body = r#"[{"remarks":"meta"},{"outbounds":[{"protocol":"vless"}]}]"#;
        assert_eq!(parse(body).unwrap().len(), 1);
    }

    #[test]
    fn rejects_unknown_bodies() {
        assert!(parse("hello").is_err());
        assert!(parse("").is_err());
        assert!(parse("{}").is_err());
        assert!(parse("[]").is_err());
    }
}
