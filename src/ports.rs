//! Sticky ports: a per-OS-user JSON ledger mapping each data root to the one
//! port its instance serves everything on, plus local hardware/compute probing.

use std::collections::HashMap;
use std::path::Path;

const SIBLING_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// One instance's ledger entry, keyed in the file by its data root.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SiblingEntry {
    pub port: u16,
    pub device_id: String,
    pub mesh_public_key: String,
    pub label: String,
    pub pid: u32,
    pub updated_at: u64,
    #[serde(default)]
    pub chip: Option<String>,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub gpu_core_count: Option<u32>,
    #[serde(default)]
    pub tflops_fp16: Option<f64>,
}

pub fn ledger_path() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("PROXY_MESH_LEDGER").filter(|v| !v.is_empty()) {
        return Some(std::path::PathBuf::from(path));
    }
    let home = std::path::PathBuf::from(std::env::var_os("HOME")?);
    let mac_caches = home.join("Library/Caches");
    let base = if mac_caches.is_dir() {
        mac_caches
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        std::path::PathBuf::from(xdg)
    } else {
        home.join(".cache")
    };
    let path = base.join("com.theproxycompany/mesh-ports.json");
    migrate_legacy_ledger(&home, &path);
    Some(path)
}

fn migrate_legacy_ledger(home: &Path, new: &Path) {
    if new.exists() {
        return;
    }
    let old = home.join("Library/Application Support/com.theproxycompany/mesh-ports.json");
    if !old.is_file() {
        return;
    }
    if let Some(parent) = new.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::rename(&old, new).is_ok() {
        return;
    }
    let _ = std::fs::copy(&old, new).and_then(|_| std::fs::remove_file(&old));
}

#[cfg(feature = "daemon")]
pub fn read_ledger(path: &Path) -> HashMap<String, SiblingEntry> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

#[cfg(feature = "daemon")]
pub fn write_ledger(path: &Path, ledger: &HashMap<String, SiblingEntry>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    std::fs::write(&temp, serde_json::to_vec_pretty(ledger).unwrap_or_default())?;
    std::fs::rename(&temp, path)
}

pub fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(feature = "daemon")]
pub fn record_port_entry(data_root: &Path, device_id_hex: &str, public_key_sec1: &[u8], port: u16) {
    let Some(path) = ledger_path() else {
        return;
    };
    let root_key = data_root.to_string_lossy().into_owned();
    let mut ledger = read_ledger(&path);
    let compute = local_compute();
    ledger.insert(
        root_key.clone(),
        SiblingEntry {
            port,
            device_id: device_id_hex.to_string(),
            mesh_public_key: hex::encode(public_key_sec1),
            label: data_root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or(root_key),
            pid: std::process::id(),
            updated_at: unix_ms(),
            chip: compute.chip.clone(),
            memory_bytes: compute.memory_bytes,
            gpu_core_count: compute.gpu_core_count,
            tflops_fp16: compute.tflops_fp16,
        },
    );
    let _ = write_ledger(&path, &ledger);
}

#[cfg(feature = "daemon")]
pub fn live_siblings(my_data_root: &Path) -> Vec<(String, SiblingEntry)> {
    let Some(path) = ledger_path() else {
        return Vec::new();
    };
    let my_root = my_data_root.to_string_lossy();
    let now = unix_ms();
    read_ledger(&path)
        .into_iter()
        .filter(|(root, entry)| {
            *root != my_root
                && pid_alive(entry.pid)
                && now.saturating_sub(entry.updated_at) <= SIBLING_MAX_AGE_MS
        })
        .collect()
}

#[cfg(feature = "daemon")]
pub fn ledger_entries() -> HashMap<String, SiblingEntry> {
    ledger_path()
        .map(|path| read_ledger(&path))
        .unwrap_or_default()
}

pub fn local_hardware_family() -> Option<String> {
    static FAMILY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    FAMILY.get_or_init(compute_hardware_family).clone()
}

#[cfg(target_os = "macos")]
fn compute_hardware_family() -> Option<String> {
    if let Some(family) = ioreg_product_name().as_deref().and_then(family_from_name) {
        return Some(family.to_string());
    }
    let identifier = local_hardware_model()?;
    Some(
        family_from_name(&identifier)
            .or_else(|| board_id_family(&identifier))
            .map(str::to_string)
            .unwrap_or(identifier),
    )
}

#[cfg(not(target_os = "macos"))]
fn compute_hardware_family() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn ioreg_product_name() -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-r", "-p", "IODeviceTree", "-n", "product", "-d", "1"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"product-name\" = <\""))?;
    Some(value.strip_suffix("\">")?.to_string())
}

#[cfg(target_os = "macos")]
fn family_from_name(name: &str) -> Option<&'static str> {
    const KEYWORDS: [(&str, &str); 14] = [
        ("macbook pro", "MacBook Pro"),
        ("macbookpro", "MacBook Pro"),
        ("macbook air", "MacBook Air"),
        ("macbookair", "MacBook Air"),
        ("mac studio", "Mac Studio"),
        ("macstudio", "Mac Studio"),
        ("mac mini", "Mac mini"),
        ("macmini", "Mac mini"),
        ("imac", "iMac"),
        ("mac pro", "Mac Pro"),
        ("macpro", "Mac Pro"),
        ("macbook", "MacBook"),
        ("iphone", "iPhone"),
        ("ipad", "iPad"),
    ];
    let lowered = name.to_lowercase();
    KEYWORDS
        .iter()
        .find(|(keyword, _)| lowered.contains(keyword))
        .map(|(_, family)| *family)
}

#[cfg(target_os = "macos")]
fn board_id_family(board_id: &str) -> Option<&'static str> {
    Some(match board_id {
        "Mac13,1" | "Mac13,2" | "Mac14,13" | "Mac14,14" | "Mac15,14" | "Mac16,9" => "Mac Studio",
        "Mac14,3" | "Mac14,12" | "Mac16,10" | "Mac16,11" => "Mac mini",
        "Mac14,8" => "Mac Pro",
        "Mac15,4" | "Mac15,5" | "Mac16,2" | "Mac16,3" => "iMac",
        "Mac14,2" | "Mac14,15" | "Mac15,12" | "Mac15,13" | "Mac16,12" | "Mac16,13" | "Mac17,3"
        | "Mac17,4" => "MacBook Air",
        "Mac14,5" | "Mac14,6" | "Mac14,7" | "Mac14,9" | "Mac14,10" | "Mac15,3" | "Mac15,6"
        | "Mac15,7" | "Mac15,8" | "Mac15,9" | "Mac15,10" | "Mac15,11" | "Mac16,1" | "Mac16,5"
        | "Mac16,6" | "Mac16,7" | "Mac16,8" | "Mac17,2" | "Mac17,6" | "Mac17,7" | "Mac17,8"
        | "Mac17,9" => "MacBook Pro",
        "Mac17,5" => "MacBook",
        _ => return None,
    })
}

#[cfg(target_os = "macos")]
fn local_hardware_model() -> Option<String> {
    sysctl_string(b"hw.model\0")
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &[u8]) -> Option<String> {
    unsafe {
        let name = name.as_ptr().cast();
        let mut len = 0usize;
        if libc::sysctlbyname(
            name,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
            || len == 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(
            name,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        buf.truncate(len);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).ok()
    }
}

#[derive(Default, Clone, Debug)]
pub struct LocalCompute {
    pub chip: Option<String>,
    pub memory_bytes: Option<u64>,
    pub gpu_core_count: Option<u32>,
    pub tflops_fp16: Option<f64>,
}

pub fn local_compute() -> &'static LocalCompute {
    static COMPUTE: std::sync::OnceLock<LocalCompute> = std::sync::OnceLock::new();
    COMPUTE.get_or_init(compute_local_compute)
}

#[cfg(target_os = "macos")]
fn compute_local_compute() -> LocalCompute {
    let chip = sysctl_string(b"machdep.cpu.brand_string\0");
    let gpu_core_count = agx_gpu_core_count();
    LocalCompute {
        memory_bytes: sysctl_u64(b"hw.memsize\0"),
        tflops_fp16: tflops_fp16(chip.as_deref(), gpu_core_count),
        chip,
        gpu_core_count,
    }
}

#[cfg(not(target_os = "macos"))]
fn compute_local_compute() -> LocalCompute {
    LocalCompute::default()
}

#[cfg(target_os = "macos")]
pub fn sysctl_u64(name: &[u8]) -> Option<u64> {
    unsafe {
        let mut value: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        (libc::sysctlbyname(
            name.as_ptr().cast(),
            (&mut value as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) == 0)
            .then_some(value)
    }
}

#[cfg(target_os = "macos")]
fn agx_gpu_core_count() -> Option<u32> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-r", "-c", "AGXAccelerator", "-d", "1"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"gpu-core-count\" = "))?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn tflops_fp16(chip: Option<&str>, gpu_core_count: Option<u32>) -> Option<f64> {
    let generation = chip?.split_whitespace().find(|token| {
        token
            .strip_prefix('M')
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    })?;
    let per_core = match generation {
        "M1" => 0.325,
        "M2" | "M3" => 0.358,
        "M4" => 0.404,
        _ => return None,
    };
    Some(per_core * f64::from(gpu_core_count?))
}
