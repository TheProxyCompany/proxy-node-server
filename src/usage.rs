//! Rolling local GPU & memory usage telemetry for the `proxy.ing` registry heartbeat.

#[cfg(target_os = "macos")]
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UsageSnapshot {
    pub gpu_pct_1m: f64,
    pub gpu_pct_15m: f64,
    pub mem_used_bytes: u64,
    pub sampled_at: String,
}

#[cfg(target_os = "macos")]
const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "macos")]
const RING_CAP: usize = 180;

#[cfg(target_os = "macos")]
fn samples() -> &'static Mutex<VecDeque<(u64, f64)>> {
    static SAMPLER: OnceLock<Mutex<VecDeque<(u64, f64)>>> = OnceLock::new();
    SAMPLER.get_or_init(|| {
        std::thread::Builder::new()
            .name("mesh-usage-sampler".into())
            .spawn(sample_loop)
            .ok();
        Mutex::new(VecDeque::new())
    })
}

#[cfg(target_os = "macos")]
fn sample_loop() {
    loop {
        if let Some(pct) = read_gpu_utilization() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok(mut ring) = samples().lock() {
                ring.push_back((now, pct));
                while ring.len() > RING_CAP {
                    ring.pop_front();
                }
            }
        }
        std::thread::sleep(SAMPLE_INTERVAL);
    }
}

#[cfg(target_os = "macos")]
fn read_gpu_utilization() -> Option<f64> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-r", "-c", "AGXAccelerator", "-d", "1"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_device_utilization(&stdout)
}

#[cfg(target_os = "macos")]
fn parse_device_utilization(stdout: &str) -> Option<f64> {
    let dict = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"PerformanceStatistics\" = {"))?;
    let (_, rest) = dict.split_once("\"Device Utilization %\"=")?;
    let digits = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .filter(|d| !d.is_empty())?;
    digits.parse().ok()
}

#[cfg(target_os = "macos")]
fn window_mean(ring: &VecDeque<(u64, f64)>, newest_ms: u64, span_ms: u64) -> Option<f64> {
    let cutoff = newest_ms.saturating_sub(span_ms);
    let window: Vec<f64> = ring
        .iter()
        .filter(|(ts, _)| *ts >= cutoff)
        .map(|(_, pct)| *pct)
        .collect();
    (!window.is_empty()).then(|| window.iter().sum::<f64>() / window.len() as f64)
}

#[cfg(target_os = "macos")]
fn mem_used_bytes() -> Option<u64> {
    let total = crate::ports::sysctl_u64(b"hw.memsize\0")?;
    let free_pages = crate::ports::sysctl_u64(b"vm.page_free_count\0")?;
    let page_size = crate::ports::sysctl_u64(b"hw.pagesize\0")?;
    Some(total.saturating_sub(free_pages * page_size))
}

#[cfg(target_os = "macos")]
pub fn snapshot() -> Option<UsageSnapshot> {
    let ring = samples().lock().ok()?;
    let (newest_ms, _) = *ring.back()?;
    let gpu_pct_1m = window_mean(&ring, newest_ms, 60_000)?;
    let gpu_pct_15m = window_mean(&ring, newest_ms, 900_000)?;
    drop(ring);
    let secs = (newest_ms / 1000) as i64;
    let sampled_at = format!("{secs}");
    Some(UsageSnapshot {
        gpu_pct_1m,
        gpu_pct_15m,
        mem_used_bytes: mem_used_bytes()?,
        sampled_at,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn snapshot() -> Option<UsageSnapshot> {
    None
}
