//! Tailnet presence (feature `discovery-tailscale`), by shelling the local
//! `tailscale` LocalAPI rather than embedding a tsnet node (see the phase-2
//! design's reality check: the official `tailscale-rs` tsnet preview is
//! experimental and would run a second userspace node inside the process).
//! Enumerates online tailnet peers from `tailscale status --json` and probes
//! each for a live node server on the mesh port.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;
use thiserror::Error;

use super::{LocalAdvert, PeerInfo, PresenceProvider};
use crate::net::HttpPullSource;

#[derive(Debug, Error)]
pub enum TailscaleError {
    #[error("spawn tailscale: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("tailscale status exited non-zero: {0}")]
    Status(String),
    #[error("parse tailscale status json: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Discovers peers over an already-running `tailscaled`. `advertise` is a no-op:
/// the tailnet already publishes the host, so a peer is found by probing its
/// tailnet IP on the mesh port.
pub struct TailscaleProvider {
    binary: String,
    mesh_port: u16,
}

impl TailscaleProvider {
    pub fn new(mesh_port: u16) -> Self {
        Self {
            binary: "tailscale".into(),
            mesh_port,
        }
    }

    /// Override the `tailscale` executable (e.g. an absolute path).
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }
}

impl PresenceProvider for TailscaleProvider {
    type Error = TailscaleError;

    async fn advertise(&self, _me: &LocalAdvert) -> Result<(), TailscaleError> {
        Ok(())
    }

    async fn browse(&self) -> Result<Vec<PeerInfo>, TailscaleError> {
        let output = tokio::process::Command::new(&self.binary)
            .args(["status", "--json"])
            .output()
            .await?;
        if !output.status.success() {
            return Err(TailscaleError::Status(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        let status: Status = serde_json::from_slice(&output.stdout)?;

        // Collect every online peer's mesh-port addresses, then probe them all
        // concurrently. Sequential probing let one blackholed tailnet IP hang
        // the whole browse tick; join_all bounds the tick at a single probe's
        // timeout (each `fetch_head` carries `HttpPullSource`'s default).
        let probes = status.peer.values().filter(|peer| peer.online).map(|peer| {
            let addrs: Vec<SocketAddr> = peer
                .tailscale_ips
                .iter()
                .filter_map(|raw| raw.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, self.mesh_port))
                .collect();
            probe_peer(addrs)
        });
        let peers = futures_util::future::join_all(probes)
            .await
            .into_iter()
            .flatten()
            .collect();
        Ok(peers)
    }
}

/// Probe a peer's addresses in order, surfacing the first that answers a live
/// node server. Most tailnet peers are not running the mesh, so a peer that
/// answers on none of its addresses yields `None`. Each probe is bounded by
/// `HttpPullSource`'s default request timeout, so a blackholed address returns
/// after that timeout instead of hanging.
async fn probe_peer(addrs: Vec<SocketAddr>) -> Option<PeerInfo> {
    for addr in addrs {
        let base_url = format!("http://{addr}");
        if HttpPullSource::new(&base_url).fetch_head().await.is_ok() {
            return Some(PeerInfo {
                device_id: None,
                addrs: vec![addr],
                base_url: Some(base_url),
                source: "tailscale",
            });
        }
    }
    None
}

/// The subset of `tailscale status --json` the provider reads.
#[derive(Deserialize)]
struct Status {
    #[serde(rename = "Peer", default)]
    peer: HashMap<String, Peer>,
}

#[derive(Deserialize)]
struct Peer {
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Online", default)]
    online: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_online_peers_from_status_json() {
        let json = br#"{
            "Peer": {
                "node-a": { "TailscaleIPs": ["100.64.0.1", "fd7a::1"], "Online": true },
                "node-b": { "TailscaleIPs": ["100.64.0.2"], "Online": false }
            }
        }"#;
        let status: Status = serde_json::from_slice(json).unwrap();
        assert_eq!(status.peer.len(), 2);
        let a = &status.peer["node-a"];
        assert!(a.online);
        assert_eq!(a.tailscale_ips, vec!["100.64.0.1", "fd7a::1"]);
        assert!(!status.peer["node-b"].online);
    }

    // A trimmed status (fields absent) must not fail the parse: default to no
    // peers rather than erroring the whole browse.
    #[test]
    fn tolerates_missing_fields() {
        let status: Status = serde_json::from_slice(b"{}").unwrap();
        assert!(status.peer.is_empty());
    }
}
