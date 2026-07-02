//! Provider-agnostic peer discovery (feature `discovery`).
//!
//! Two seams, deliberately separate so a provider can supply one without the
//! other: [`PresenceProvider`] finds/advertises peers, [`PeerTransport`] builds
//! an authenticated [`PullSource`] to one. proxy.ing can supply presence while
//! HTTP supplies transport; Tailscale supplies both. Concrete providers live
//! behind their own features ([`mdns`], [`tailscale`]) so a default build pulls
//! in none of their dependencies.
//!
//! Discovery output is always a *hint*: the real trust decision is still
//! [`register_peer`](crate::net::register_peer) fetching `/identity` and every
//! op being signature-verified against the exact advertised key. A forged TXT
//! record or a hijacked address can only point a puller at a node whose ops it
//! will then reject.

use std::net::SocketAddr;

use crate::error::TransportError;
use crate::identity::DeviceId;
use crate::net::HttpPullSource;
use crate::transport::PullSource;

#[cfg(feature = "discovery-mdns")]
pub mod mdns;
#[cfg(feature = "discovery-tailscale")]
pub mod tailscale;

/// A peer as a discovery provider sees it, before `/identity` confirms who it
/// is. `device_id` may be unknown until the puller fetches `/identity`.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Advertised device id, if the provider carried one (e.g. an mDNS TXT
    /// record). Never trusted until `/identity` re-derives it from the key.
    pub device_id: Option<DeviceId>,
    /// Reachable endpoints (LAN ip, tailnet ip) for the mesh port.
    pub addrs: Vec<SocketAddr>,
    /// Base URL for HTTP pull providers (e.g. a proxy.ing hostname).
    pub base_url: Option<String>,
    /// Which provider surfaced this peer: `"mdns" | "proxy-ing" | "tailscale"`.
    pub source: &'static str,
}

impl PeerInfo {
    /// The base URL to pull from: an explicit `base_url`, else the first
    /// reachable address as `http://addr`.
    pub fn resolve_base_url(&self) -> Option<String> {
        self.base_url
            .clone()
            .or_else(|| self.addrs.first().map(|a| format!("http://{a}")))
    }
}

/// What a node advertises so peers can find it. TXT-record sized.
#[derive(Clone, Debug)]
pub struct LocalAdvert {
    pub device_id: DeviceId,
    pub mesh_port: u16,
    pub public_key_sec1: [u8; 33],
}

/// Advertise this node and enumerate currently-present peers. Async because the
/// only implementors are I/O-backed (mDNS sockets, a `tailscale` subprocess).
#[allow(async_fn_in_trait)] // callers are the single pull loop; no Send bound needed
pub trait PresenceProvider {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Announce this node so peers can discover it. A no-op for providers whose
    /// addressing layer already advertises the host (e.g. Tailscale).
    async fn advertise(&self, me: &LocalAdvert) -> Result<(), Self::Error>;

    /// The peers present right now. Called each pull tick; the pull loop
    /// reconciles the returned set against its active targets.
    async fn browse(&self) -> Result<Vec<PeerInfo>, Self::Error>;
}

/// Build an authenticated pull source to a discovered peer. Separate from
/// presence so a proxy.ing-style presence provider can share the plain HTTP
/// transport with mDNS.
pub trait PeerTransport {
    type Source: PullSource;
    type Error: std::error::Error + Send + Sync + 'static;

    fn connect(&self, peer: &PeerInfo) -> Result<Self::Source, Self::Error>;
}

/// The reference transport: plain HTTP pull over a peer's base URL or address.
/// Used by every pull-http presence provider (mDNS, proxy.ing, Tailscale).
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpTransport;

impl PeerTransport for HttpTransport {
    type Source = HttpPullSource;
    type Error = TransportError;

    fn connect(&self, peer: &PeerInfo) -> Result<HttpPullSource, TransportError> {
        let base = peer
            .resolve_base_url()
            .ok_or_else(|| TransportError::Wire("peer has no reachable address".into()))?;
        Ok(HttpPullSource::new(base))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_base_url_prefers_explicit_then_first_addr() {
        let explicit = PeerInfo {
            device_id: None,
            addrs: vec!["10.0.0.2:51714".parse().unwrap()],
            base_url: Some("https://desk.example.proxy.ing".into()),
            source: "proxy-ing",
        };
        assert_eq!(
            explicit.resolve_base_url().as_deref(),
            Some("https://desk.example.proxy.ing")
        );

        let addr_only = PeerInfo {
            device_id: None,
            addrs: vec!["10.0.0.2:51714".parse().unwrap()],
            base_url: None,
            source: "tailscale",
        };
        assert_eq!(
            addr_only.resolve_base_url().as_deref(),
            Some("http://10.0.0.2:51714")
        );

        let nothing = PeerInfo {
            device_id: None,
            addrs: vec![],
            base_url: None,
            source: "mdns",
        };
        assert_eq!(nothing.resolve_base_url(), None);
        assert!(HttpTransport.connect(&nothing).is_err());
    }
}
