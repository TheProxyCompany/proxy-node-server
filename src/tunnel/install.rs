//! Cross-platform `cloudflared` binary resolution and GitHub release installer
//! (macOS `darwin-arm64`/`darwin-amd64` `.tgz` and Linux `linux-arm64`/`linux-amd64` binary).

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::process::Command;

use super::{InstallProgress, TunnelManager};

pub fn managed_cloudflared_path() -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "Could not resolve HOME directory".to_string())?;
        Ok(home.join("Library/Application Support/com.TheProxyCompany.Eden/bin/cloudflared"))
    } else {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .ok_or_else(|| "Could not resolve data directory".to_string())?;
        Ok(base.join("proxy-node-server/bin/cloudflared"))
    }
}

fn cloudflared_release_url() -> (&'static str, bool) {
    if cfg!(target_os = "macos") {
        if cfg!(target_arch = "x86_64") {
            (
                "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
                true,
            )
        } else {
            (
                "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz",
                true,
            )
        }
    } else if cfg!(target_arch = "aarch64") {
        (
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
            false,
        )
    } else {
        (
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
            false,
        )
    }
}

impl TunnelManager {
    pub async fn which_cloudflared(&self) -> Result<String, String> {
        let managed = managed_cloudflared_path()?;
        if managed.exists() {
            return Ok(managed.to_string_lossy().to_string());
        }

        if let Ok(output) = Command::new("which").arg("cloudflared").output().await {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }

        self.install_cloudflared(&managed).await?;
        Ok(managed.to_string_lossy().to_string())
    }

    async fn install_cloudflared(&self, dest: &Path) -> Result<(), String> {
        let result = self.install_cloudflared_inner(dest).await;
        self.set_install_state(None).await;
        result
    }

    async fn install_cloudflared_inner(&self, dest: &Path) -> Result<(), String> {
        let parent = dest
            .parent()
            .ok_or_else(|| "Managed cloudflared path has no parent".to_string())?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| format!("Failed to create {}: {}", parent.display(), err))?;

        let (url, is_tgz) = cloudflared_release_url();

        self.set_install_state(Some(InstallProgress {
            phase: "downloading".to_string(),
            progress: 0.0,
        }))
        .await;

        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|err| format!("Failed to build HTTP client: {}", err))?
            .get(url)
            .send()
            .await
            .map_err(|err| format!("Failed to download cloudflared: {}", err))?
            .error_for_status()
            .map_err(|err| format!("cloudflared download returned error: {}", err))?;

        let total_size = response.content_length();
        let mut stream = response.bytes_stream();
        let mut bytes: Vec<u8> = match total_size {
            Some(n) => Vec::with_capacity(n as usize),
            None => Vec::new(),
        };
        let mut downloaded: u64 = 0;
        let mut last_reported: f64 = 0.0;

        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|err| format!("cloudflared download stream error: {}", err))?;
            bytes.extend_from_slice(&chunk);
            downloaded += chunk.len() as u64;
            if let Some(total) = total_size {
                if total > 0 {
                    let progress = (downloaded as f64 / total as f64).min(1.0);
                    if progress - last_reported >= 0.01 || progress >= 1.0 {
                        last_reported = progress;
                        self.set_install_state(Some(InstallProgress {
                            phase: "downloading".to_string(),
                            progress,
                        }))
                        .await;
                    }
                }
            }
        }

        self.set_install_state(Some(InstallProgress {
            phase: "extracting".to_string(),
            progress: 0.0,
        }))
        .await;

        let dest_path = dest.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            if is_tgz {
                let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
                let mut archive = tar::Archive::new(decoder);
                let mut found = false;
                for entry in archive
                    .entries()
                    .map_err(|err| format!("Failed to read tarball: {}", err))?
                {
                    let mut entry = entry.map_err(|err| format!("Tarball entry error: {}", err))?;
                    let entry_path = entry
                        .path()
                        .map_err(|err| format!("Tarball entry path error: {}", err))?
                        .to_path_buf();
                    let file_name = entry_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    if file_name == "cloudflared" {
                        entry
                            .unpack(&dest_path)
                            .map_err(|err| format!("Failed to extract cloudflared: {}", err))?;
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err("Tarball did not contain a cloudflared binary".into());
                }
            } else {
                std::fs::write(&dest_path, &bytes)
                    .map_err(|err| format!("Failed to write cloudflared: {}", err))?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dest_path)
                    .map_err(|err| format!("stat after extract failed: {}", err))?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dest_path, perms)
                    .map_err(|err| format!("chmod cloudflared failed: {}", err))?;
            }
            Ok(())
        })
        .await
        .map_err(|err| format!("cloudflared extraction task panicked: {}", err))??;

        self.set_install_state(Some(InstallProgress {
            phase: "finalizing".to_string(),
            progress: 1.0,
        }))
        .await;

        Ok(())
    }
}
