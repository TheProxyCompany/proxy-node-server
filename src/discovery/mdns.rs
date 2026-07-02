//! mDNS/Bonjour LAN presence (feature `discovery-mdns`), backed by the
//! pure-Rust `mdns-sd`. Advertises `_proxy-node._tcp.local.` with the device id
//! and key in TXT, and browses the same type into [`PeerInfo`]s. The TXT id/key
//! are hints only — [`register_peer`](crate::net::register_peer) still confirms
//! identity and every op is signature-checked.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use thiserror::Error;

use super::{LocalAdvert, PeerInfo, PresenceProvider};
use crate::identity::DeviceId;

/// The service type this mesh advertises and browses.
pub const SERVICE_TYPE: &str = "_proxy-node._tcp.local.";

#[derive(Debug, Error)]
pub enum MdnsError {
    #[error("mdns error: {0}")]
    Mdns(#[from] mdns_sd::Error),
}

/// An mDNS presence provider. A background thread drains the browse channel into
/// a resolved-peer cache so [`browse`](PresenceProvider::browse) is a cheap
/// snapshot on each pull tick.
pub struct MdnsProvider {
    daemon: ServiceDaemon,
    resolved: Arc<Mutex<HashMap<String, PeerInfo>>>,
    _browser: JoinHandle<()>,
}

impl MdnsProvider {
    pub fn new() -> Result<Self, MdnsError> {
        let daemon = ServiceDaemon::new()?;
        let receiver = daemon.browse(SERVICE_TYPE)?;
        let resolved: Arc<Mutex<HashMap<String, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
        let cache = resolved.clone();
        let browser = std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(svc) => {
                        if let Some(peer) = peer_from_resolved(&svc) {
                            cache
                                .lock()
                                .expect("mdns cache poisoned")
                                .insert(svc.fullname.clone(), peer);
                        }
                    }
                    ServiceEvent::ServiceRemoved(_ty, fullname) => {
                        cache.lock().expect("mdns cache poisoned").remove(&fullname);
                    }
                    _ => {}
                }
            }
        });
        Ok(Self {
            daemon,
            resolved,
            _browser: browser,
        })
    }
}

impl PresenceProvider for MdnsProvider {
    type Error = MdnsError;

    async fn advertise(&self, me: &LocalAdvert) -> Result<(), MdnsError> {
        let id_hex = me.device_id.to_hex();
        let instance = &id_hex[..16];
        let host = format!("{instance}.local.");
        let pk_hex = hex(&me.public_key_sec1);
        // Empty ip + enable_addr_auto lets mdns-sd fill in this host's live
        // interface addresses and keep them current.
        let props: [(&str, &str); 3] = [
            ("device_id", id_hex.as_str()),
            ("pk", pk_hex.as_str()),
            ("v", "1"),
        ];
        let service =
            ServiceInfo::new(SERVICE_TYPE, instance, &host, "", me.mesh_port, &props[..])?
                .enable_addr_auto();
        self.daemon.register(service)?;
        Ok(())
    }

    async fn browse(&self) -> Result<Vec<PeerInfo>, MdnsError> {
        Ok(self
            .resolved
            .lock()
            .expect("mdns cache poisoned")
            .values()
            .cloned()
            .collect())
    }
}

fn peer_from_resolved(svc: &ResolvedService) -> Option<PeerInfo> {
    let port = svc.port;
    let addrs: Vec<SocketAddr> = svc
        .addresses
        .iter()
        .map(|scoped| SocketAddr::new(scoped.to_ip_addr(), port))
        .collect();
    let base_url = addrs.first().map(|a| format!("http://{a}"))?;
    let device_id = svc
        .txt_properties
        .get_property_val_str("device_id")
        .and_then(|s| DeviceId::from_hex(s).ok());
    Some(PeerInfo {
        device_id,
        addrs,
        base_url: Some(base_url),
        source: "mdns",
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
