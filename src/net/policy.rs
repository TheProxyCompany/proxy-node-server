//! Peer URL parsing and transport confidentiality policy for the Proxy mesh.
//!
//! Mesh traffic may traverse `https://` endpoints, loopback `http://`
//! (`localhost`, `127.0.0.0/8`, `::1`), or the encrypted Tailscale address
//! ranges (`100.64.0.0/10` IPv4 CGNAT and `fd7a:115c:a1e0::/48` IPv6 ULA).
//! Plaintext LAN or public `http://` endpoints and URLs carrying credentials,
//! non-root paths, query strings, or fragments are rejected.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// Environment variable listing comma-separated trusted peer base URLs
/// (`http://100.78.0.54:51712,...`).
pub const MESH_PEERS_ENV: &str = "PROXY_MESH_PEERS";

/// Environment variable (`PROXY_MESH_AUDIT=1`) instructing a v3 puller/server
/// to ignore coverage claims on the keyed channel.
pub const MESH_AUDIT_ENV: &str = "PROXY_MESH_AUDIT";

/// Parse [`MESH_PEERS_ENV`] (`PROXY_MESH_PEERS`) into a de-duplicated list of
/// normalized peer base URLs (trimmed, trailing `/` stripped).
pub fn parse_mesh_peers() -> Vec<String> {
    let Ok(raw) = std::env::var(MESH_PEERS_ENV) else {
        return Vec::new();
    };
    parse_mesh_peers_from(&raw)
}

/// Parse a comma-separated peer list string into a de-duplicated list of
/// normalized peer base URLs.
pub fn parse_mesh_peers_from(raw: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert((*s).to_string()))
        .map(str::to_string)
        .collect()
}

/// Whether `host` (with or without IPv6 brackets) names a loopback address
/// (`localhost`, `127.0.0.0/8`, or `::1`).
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether `ip` lies inside the encrypted Tailscale address space:
/// IPv4 CGNAT (`100.64.0.0/10`) or IPv6 Tailscale ULA (`fd7a:115c:a1e0::/48`).
pub fn is_cgnat_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

/// Whether `endpoint` is a clean base URL (`scheme://host[:port][/]`, no
/// userinfo, query, fragment, or sub-path) over a confidential transport:
/// `https://`, loopback `http://`, or Tailscale CGNAT/ULA `http://`.
pub fn endpoint_has_confidential_transport(endpoint: &str) -> bool {
    let Some((scheme, host)) = parse_base_endpoint_host(endpoint) else {
        return false;
    };
    if scheme == "https" {
        return true;
    }
    if scheme != "http" {
        return false;
    }
    if is_loopback_host(host) {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(is_cgnat_ip)
}

fn parse_base_endpoint_host(endpoint: &str) -> Option<(&str, &str)> {
    if endpoint.bytes().any(|b| b <= b' ' || b == b'\x7f') {
        return None;
    }
    if endpoint.contains(['@', '?', '#', '\\']) {
        return None;
    }
    let (scheme, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        ("https", rest)
    } else {
        let rest = endpoint.strip_prefix("http://")?;
        ("http", rest)
    };
    let authority = match rest.split_once('/') {
        None => rest,
        Some((auth, "")) => auth,
        Some((_, _non_empty_path)) => return None,
    };
    if authority.is_empty() {
        return None;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let (ipv6, after) = bracketed.split_once(']')?;
        if !after.is_empty() {
            let port = after.strip_prefix(':')?;
            if port.is_empty() || port.parse::<u16>().is_err() {
                return None;
            }
        }
        ipv6.parse::<std::net::Ipv6Addr>().ok()?;
        ipv6
    } else if let Some((h, port)) = authority.rsplit_once(':') {
        if h.contains(':') || port.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        h
    } else {
        authority
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_deduplicates_mesh_peers() {
        let parsed = parse_mesh_peers_from(
            " http://127.0.0.1:51712/ , https://node.proxy.ing/ , http://127.0.0.1:51712 , ",
        );
        assert_eq!(
            parsed,
            vec![
                "http://127.0.0.1:51712".to_string(),
                "https://node.proxy.ing".to_string(),
            ]
        );
    }

    #[test]
    fn loopback_and_cgnat_classifiers_match_tailnet_and_localhost() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("192.168.1.1"));

        assert!(is_cgnat_ip("100.64.0.1".parse().unwrap()));
        assert!(is_cgnat_ip("100.127.255.254".parse().unwrap()));
        assert!(!is_cgnat_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_cgnat_ip("100.128.0.1".parse().unwrap()));
        assert!(is_cgnat_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!is_cgnat_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn endpoint_confidentiality_enforces_scheme_host_and_clean_root_url() {
        assert!(endpoint_has_confidential_transport(
            "https://alice.proxy.ing"
        ));
        assert!(endpoint_has_confidential_transport(
            "https://alice.proxy.ing:8443/"
        ));
        assert!(endpoint_has_confidential_transport(
            "http://localhost:51712"
        ));
        assert!(endpoint_has_confidential_transport(
            "http://127.0.0.1:51712/"
        ));
        assert!(endpoint_has_confidential_transport("http://[::1]:51712"));
        assert!(endpoint_has_confidential_transport(
            "http://100.78.0.54:51712"
        ));
        assert!(endpoint_has_confidential_transport(
            "http://[fd7a:115c:a1e0::1234]:51712"
        ));

        assert!(!endpoint_has_confidential_transport(
            "http://192.168.1.20:51712"
        ));
        assert!(!endpoint_has_confidential_transport(
            "http://alice.proxy.ing"
        ));
        assert!(!endpoint_has_confidential_transport(
            "https://user:pass@alice.proxy.ing"
        ));
        assert!(!endpoint_has_confidential_transport(
            "https://alice.proxy.ing/mesh"
        ));
        assert!(!endpoint_has_confidential_transport(
            "https://alice.proxy.ing?x=1"
        ));
        assert!(!endpoint_has_confidential_transport(
            "https://alice.proxy.ing#frag"
        ));
    }
}
