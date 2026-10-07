//! One Proxy-owned local engine allocates ports for all of this user's
//! profiles. Each data root retains a distinct sandbox registry and namespace.
//! Lima canonicalizes its socket paths, so its physical home must be short.
use super::HostError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
struct Reference {
    version: u32,
    root: PathBuf,
    home: PathBuf,
    namespace: String,
}

#[cfg(target_os = "macos")]
pub(super) fn open(root: &Path) -> Result<(PathBuf, String), HostError> {
    use rand_core::RngCore;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let root = root.canonicalize()?;
    let owner = std::fs::metadata(&root)?.uid();
    let home = PathBuf::from(format!("/Users/Shared/.pxc-{owner}/runtime"));
    let bucket = home.parent().expect("runtime parent");
    let created = match std::fs::DirBuilder::new().mode(0o700).create(bucket) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    check_directory(bucket, owner)?;
    let marker = bucket.join("owner");
    let expected = format!("proxy-node-server:cua-runtime-homes:v1:{owner}\n");
    if created {
        create_file(&marker, expected.as_bytes())?;
    }
    // A second profile may arrive between private mkdir and marker publication.
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    check_file(&marker, owner)?;
    if std::fs::read_to_string(&marker)? != expected {
        return Err(HostError::Forbidden);
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&home) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check_directory(&home, owner)?;
    if home.canonicalize()? != home {
        return Err(HostError::Forbidden);
    }
    let reference = root.join("runtime-home.json");
    let record: Reference = match std::fs::read(&reference) {
        Ok(bytes) => {
            check_file(&reference, owner)?;
            serde_json::from_slice(&bytes)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut nonce = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut nonce);
            let mut hash = Sha256::new();
            hash.update(root.as_os_str().as_encoded_bytes());
            hash.update(nonce);
            let namespace = hash.finalize()[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let record = Reference {
                version: 2,
                root: root.clone(),
                home: home.clone(),
                namespace,
            };
            create_file(&reference, &serde_json::to_vec(&record)?)?;
            record
        }
        Err(error) => return Err(error.into()),
    };
    if record.version != 2
        || record.root != root
        || record.home != home
        || record.namespace.len() != 16
        || !record
            .namespace
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HostError::Invalid(
            "Cua runtime ownership reference differs; explicit migration is required".into(),
        ));
    }
    Ok((home, record.namespace))
}

#[cfg(target_os = "macos")]
fn check_directory(path: &Path, owner: u32) -> Result<(), HostError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(HostError::Forbidden);
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn check_file(path: &Path, owner: u32) -> Result<(), HostError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(HostError::Forbidden);
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn create_file(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension(format!("{}.creating", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let result = std::fs::hard_link(&temporary, path);
    std::fs::remove_file(temporary)?;
    result?;
    std::fs::File::open(path.parent().expect("reference parent"))?.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn open(root: &Path) -> Result<(PathBuf, String), HostError> {
    let root = root.canonicalize()?;
    let namespace = Sha256::digest(root.as_os_str().as_encoded_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((root, namespace))
}

/// Serializes provisioning across independent Proxy profiles/processes, not
/// their computer actions. Cua can keep serving every already-running guest.
pub(super) async fn lock(home: &Path) -> Result<std::fs::File, HostError> {
    let path = home.join("proxy-provision.lock");
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(HostError::Forbidden);
        }
        let file = options.open(path)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(file)
    })
    .await
    .map_err(|_| HostError::Stopped)?
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn long_profiles_share_only_the_owned_engine_and_keep_distinct_namespaces() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory
            .path()
            .join("a-very-long-proxy-preview-data-root-for-native-guest-proof/Runtime/Cua");
        let second = directory
            .path()
            .join("another-independent-long-proxy-preview-data-root/Runtime/Cua");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let a = open(&first).unwrap();
        let b = open(&second).unwrap();
        assert_eq!(a.0, b.0);
        assert_ne!(a.1, b.1);
        assert_eq!(open(&first).unwrap(), a);
        assert_eq!(a.0.canonicalize().unwrap(), a.0);
        assert!(
            a.0.join("runtimes/linux/vm/_lima/colima-cua/ssh.sock.1234567890123456")
                .as_os_str()
                .len()
                < 104
        );
        assert!(first.join("runtime-home.json").is_file());
    }
    #[test]
    fn another_profiles_reference_is_never_adopted_or_rewritten() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("first");
        std::fs::create_dir_all(&root).unwrap();
        open(&root).unwrap();
        let path = root.join("runtime-home.json");
        let mut other: Reference = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        other.root = directory.path().join("other");
        let bytes = serde_json::to_vec(&other).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(open(&root).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
