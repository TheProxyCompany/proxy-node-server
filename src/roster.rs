//! `proxy.ing` account-feed parsing (`GET /devices`), shared-key deduplication,
//! grace-window roster reconciliation, and tailnet endpoint discovery.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use base64::Engine as _;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;

use crate::identity::{DeviceId, DeviceIdentity};

pub const RECENT_PULL_GRACE: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug)]
pub struct CandidatePeer {
    pub device_id: String,
    pub is_self: bool,
    pub label: Option<String>,
    pub hardware_model: Option<String>,
    pub device_kind: Option<String>,
    pub owner: bool,
    pub mesh_public_key_hex: Option<String>,
    pub owner_key_hex: Option<String>,
    pub endpoints: Vec<String>,
    pub last_seen_at: Option<String>,
    pub chip: Option<String>,
    pub memory_bytes: Option<u64>,
    pub gpu_core_count: Option<u32>,
    pub tflops_fp16: Option<f64>,
    pub always_on: Option<bool>,
    pub always_on_ready: bool,
    pub account_authenticated: bool,
}

#[derive(Clone, Debug)]
pub struct MeshLinkStatus {
    pub base_url: String,
    pub registered: bool,
    pub last_pull_at: Option<u64>,
    pub applied_total: u64,
    pub behind: u64,
}

pub fn local_endpoints(mesh_port: u16) -> Vec<String> {
    let mut tailnet = Vec::new();
    #[cfg(unix)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Vec::new();
        }
        let mut cursor = ifap;
        while !cursor.is_null() {
            let entry = &*cursor;
            cursor = entry.ifa_next;
            if entry.ifa_addr.is_null()
                || (*entry.ifa_addr).sa_family as libc::c_int != libc::AF_INET
            {
                continue;
            }
            let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            if ip.is_loopback() {
                continue;
            }
            let endpoint = format!("http://{ip}:{mesh_port}");
            if ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]) {
                tailnet.push(endpoint);
            }
        }
        libc::freeifaddrs(ifap);
    }
    tailnet.truncate(8);
    tailnet
}

pub fn decode_sec1(key_hex: &str) -> Option<[u8; 33]> {
    <[u8; 33]>::try_from(hex::decode(key_hex).ok()?.as_slice()).ok()
}

pub fn candidate_device_id(key_hex: &str) -> Option<DeviceId> {
    let sec1 = decode_sec1(key_hex)?;
    DeviceIdentity::device_id_from_sec1(&sec1).ok()
}

fn str_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn phone_signing_key_hex(device: &serde_json::Value) -> Option<String> {
    if str_field(device, "device_kind")?.as_str() != "phone" {
        return None;
    }
    let encoded = str_field(device, "public_key")?;
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&encoded))
        .ok()?;
    let key = p256::PublicKey::from_public_key_der(&der).ok()?;
    Some(hex::encode(key.to_encoded_point(true).as_bytes()))
}

fn feed_candidate(device: &serde_json::Value) -> Option<CandidatePeer> {
    Some(CandidatePeer {
        device_id: str_field(device, "device_id")?,
        is_self: device
            .get("is_self")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        label: str_field(device, "label"),
        hardware_model: str_field(device, "hardware_model"),
        device_kind: str_field(device, "device_kind"),
        owner: device
            .get("owner")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        mesh_public_key_hex: str_field(device, "mesh_public_key")
            .filter(|_| str_field(device, "device_kind").as_deref() != Some("phone"))
            .map(|key| key.to_lowercase()),
        owner_key_hex: phone_signing_key_hex(device),
        endpoints: device
            .get("mesh_endpoints")
            .and_then(serde_json::Value::as_array)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        last_seen_at: str_field(device, "last_seen_at"),
        chip: str_field(device, "chip"),
        memory_bytes: device
            .get("memory_bytes")
            .and_then(serde_json::Value::as_u64),
        gpu_core_count: device
            .get("gpu_core_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| u32::try_from(count).ok()),
        tflops_fp16: device
            .get("tflops_fp16")
            .and_then(serde_json::Value::as_f64),
        always_on: device.get("always_on").and_then(serde_json::Value::as_bool),
        always_on_ready: device
            .get("always_on_ready")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        account_authenticated: true,
    })
}

pub fn feed_candidates(json: &str) -> Result<Vec<CandidatePeer>, String> {
    let feed: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("mesh network feed: {e}"))?;
    let devices = feed
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "mesh network feed: missing devices array".to_string())?;
    Ok(devices.iter().filter_map(feed_candidate).collect())
}

fn carried_forward(kept: &CandidatePeer) -> CandidatePeer {
    CandidatePeer {
        always_on: None,
        ..kept.clone()
    }
}

pub fn reconcile_roster(
    incoming: Vec<CandidatePeer>,
    previous: &[CandidatePeer],
    recent_pulls: &HashSet<DeviceId>,
) -> Vec<CandidatePeer> {
    let mut roster = incoming;
    for kept in previous {
        if !kept.account_authenticated {
            continue;
        }
        let Some(kept_key) = kept.mesh_public_key_hex.as_deref() else {
            continue;
        };
        let Some(kept_peer) = candidate_device_id(kept_key) else {
            continue;
        };
        if !recent_pulls.contains(&kept_peer) {
            continue;
        }
        let key_present = roster.iter().any(|candidate| {
            candidate
                .mesh_public_key_hex
                .as_deref()
                .is_some_and(|key| key.eq_ignore_ascii_case(kept_key))
        });
        if key_present {
            continue;
        }
        match roster
            .iter()
            .position(|candidate| candidate.device_id == kept.device_id)
        {
            Some(index) => {
                roster[index] = carried_forward(kept);
            }
            None => {
                roster.push(carried_forward(kept));
            }
        }
    }
    roster
}

pub fn merge_shared_keys<T: Ord, F: Fn(&str) -> Option<T>>(
    candidates: Vec<CandidatePeer>,
    parse_seen: F,
) -> Vec<CandidatePeer> {
    let repeats_a_device_id = {
        let mut device_ids = HashSet::new();
        !candidates
            .iter()
            .all(|candidate| device_ids.insert(candidate.device_id.as_str()))
    };
    if repeats_a_device_id {
        return candidates;
    }
    let mut by_key: HashMap<DeviceId, Vec<usize>> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(mesh_id) = candidate
            .mesh_public_key_hex
            .as_deref()
            .and_then(candidate_device_id)
        {
            by_key.entry(mesh_id).or_default().push(index);
        }
    }
    let mut dropped = HashSet::new();
    let mut absorbed: HashMap<usize, CandidatePeer> = HashMap::new();
    for indices in by_key.values() {
        if indices.len() < 2 {
            continue;
        }
        let seen_at = |index: usize| {
            candidates[index]
                .last_seen_at
                .as_deref()
                .and_then(&parse_seen)
        };
        let kept = indices
            .iter()
            .copied()
            .find(|&index| candidates[index].is_self)
            .or_else(|| {
                indices
                    .iter()
                    .copied()
                    .min_by_key(|&index| std::cmp::Reverse(seen_at(index)))
            })
            .unwrap_or(indices[0]);
        for &index in indices {
            if index != kept {
                dropped.insert(index);
            }
        }
        absorbed.insert(kept, absorb(&candidates, kept, indices));
    }
    candidates
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !dropped.contains(index))
        .map(|(index, candidate)| absorbed.remove(&index).unwrap_or(candidate))
        .collect()
}

fn absorb(candidates: &[CandidatePeer], kept: usize, indices: &[usize]) -> CandidatePeer {
    let mut merged = candidates[kept].clone();
    for &index in indices {
        if index == kept {
            continue;
        }
        let sibling = &candidates[index];
        merged.always_on = match (merged.always_on, sibling.always_on) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, None) => None,
        };
        merged.always_on_ready |= sibling.always_on_ready;
        for endpoint in &sibling.endpoints {
            if !merged.endpoints.contains(endpoint) {
                merged.endpoints.push(endpoint.clone());
            }
        }
    }
    merged
}

pub fn feed_carries_always_on(candidates: &[CandidatePeer]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.always_on.is_some())
}

pub fn always_on_mesh_ids(candidates: &[CandidatePeer], own_mesh_id: &str) -> HashSet<String> {
    candidates
        .iter()
        .filter(|candidate| candidate.always_on == Some(true))
        .flat_map(|candidate| {
            let by_key = candidate
                .mesh_public_key_hex
                .as_deref()
                .and_then(candidate_device_id)
                .map(|device| device.to_hex());
            let own = candidate.is_self.then(|| own_mesh_id.to_string());
            by_key.into_iter().chain(own)
        })
        .collect()
}

pub fn validate_candidate_keys(
    candidates: &[CandidatePeer],
) -> Result<Vec<(DeviceId, [u8; 33])>, String> {
    let mut logical_ids = HashSet::new();
    let mut mesh_ids = HashSet::new();
    let mut keys = Vec::new();
    for candidate in candidates {
        if candidate.device_id.trim().is_empty()
            || !logical_ids.insert(candidate.device_id.as_str())
        {
            return Err(format!(
                "mesh network feed has an empty or duplicate device id: {}",
                candidate.device_id
            ));
        }
        let Some(key_hex) = candidate.mesh_public_key_hex.as_deref() else {
            continue;
        };
        let sec1 = decode_sec1(key_hex).ok_or_else(|| {
            format!(
                "mesh network feed has an invalid public key for {}",
                candidate.device_id
            )
        })?;
        let mesh_device_id = DeviceIdentity::device_id_from_sec1(&sec1).map_err(|error| {
            format!(
                "mesh network feed has an invalid curve point for {}: {error}",
                candidate.device_id
            )
        })?;
        if !mesh_ids.insert(mesh_device_id) {
            return Err(format!(
                "mesh network feed maps more than one device to key {}",
                mesh_device_id.to_hex()
            ));
        }
        keys.push((mesh_device_id, sec1));
    }
    Ok(keys)
}
