//! Op-log durability for the reference daemon: an append-only file of signed
//! envelope bytes, replayed at startup. Each accepted op is one frame — a
//! little-endian `u32` length prefix followed by [`SignedOp::to_bytes`]. The
//! file mirrors the in-memory op set (a frame is written only for ops that were
//! new to the log), and a crash mid-write leaves a truncated trailing frame that
//! is dropped on the next read: the op simply gets re-pulled from its peer.
//!
//! This is the pnsd reference embedding only. Grand Central's durability is
//! proxy.db-backed through its own [`Store`](crate::store::Store) adapter.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::DurabilityError;
use crate::log::OpLog;
use crate::op::SignedOp;
use crate::registry::DeviceRegistry;

/// Append-only writer over the op-log durability file.
pub struct OplogWriter {
    file: File,
    /// Set when a failed append could not be rolled back, leaving a torn frame
    /// at the tail. Further appends are refused: replay stops at the first
    /// corrupt frame, so anything written after it would be unreachable after
    /// a restart while the cursor advances past it.
    poisoned: bool,
    #[cfg(test)]
    fail_next_append: bool,
    #[cfg(test)]
    fail_mid_append: bool,
}

impl OplogWriter {
    /// Open (creating if absent) the durability file for appending. Write mode
    /// with an explicit seek-to-end rather than append mode: on Windows,
    /// append-mode handles get `FILE_APPEND_DATA` without `FILE_WRITE_DATA`,
    /// which makes the torn-frame rollback's `set_len` fail. This writer is
    /// the file's only writer, so seek-to-end is equivalent.
    pub fn open(path: &Path) -> Result<Self, DurabilityError> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            poisoned: false,
            #[cfg(test)]
            fail_next_append: false,
            #[cfg(test)]
            fail_mid_append: false,
        })
    }

    /// Test-only fault injection: make the next `append` fail before writing.
    #[cfg(test)]
    pub(crate) fn fail_next_append(&mut self) {
        self.fail_next_append = true;
    }

    /// Test-only fault injection: make the next `append` fail after writing
    /// the length prefix, leaving a torn frame for rollback to clean up.
    #[cfg(test)]
    pub(crate) fn fail_mid_append(&mut self) {
        self.fail_mid_append = true;
    }

    /// Append one op as a length-prefixed frame and flush it to the OS. Flush
    /// pushes the bytes past the process buffer; call [`sync_after_batch`] once
    /// per batch to force them all the way to disk before advancing a cursor.
    ///
    /// A write failure mid-frame is rolled back by truncating to the frame
    /// boundary; if the rollback itself fails the writer is poisoned and all
    /// further appends error, so a valid frame is never written after a torn
    /// one (replay would stop at the tear and lose it).
    ///
    /// [`sync_after_batch`]: OplogWriter::sync_after_batch
    pub fn append(&mut self, op: &SignedOp) -> Result<(), DurabilityError> {
        if self.poisoned {
            return Err(DurabilityError::Poisoned);
        }
        #[cfg(test)]
        if self.fail_next_append {
            self.fail_next_append = false;
            return Err(DurabilityError::Io(std::io::Error::other(
                "injected append failure",
            )));
        }
        let bytes = op.to_bytes()?;
        let start = self.file.metadata()?.len();
        if let Err(e) = self.write_frame(&bytes) {
            // Roll back to the frame boundary AND reposition the cursor there:
            // set_len does not move the write position, and writing past a
            // truncated end would zero-fill the gap into a fresh torn frame.
            let rolled_back =
                self.file.set_len(start).is_ok() && self.file.seek(SeekFrom::Start(start)).is_ok();
            if !rolled_back {
                self.poisoned = true;
            }
            return Err(e);
        }
        Ok(())
    }

    fn write_frame(&mut self, bytes: &[u8]) -> Result<(), DurabilityError> {
        let len = bytes.len() as u32;
        self.file.write_all(&len.to_le_bytes())?;
        #[cfg(test)]
        if self.fail_mid_append {
            self.fail_mid_append = false;
            return Err(DurabilityError::Io(std::io::Error::other(
                "injected mid-frame failure",
            )));
        }
        self.file.write_all(bytes)?;
        self.file.flush()?;
        Ok(())
    }

    /// fsync every frame appended so far to durable storage. Called at batch
    /// granularity by the pull loop so the op-log is on disk before any peer
    /// cursor is allowed to advance past those ops: on a crash, a persisted
    /// cursor can never point past ops the log has lost.
    pub fn sync_after_batch(&mut self) -> Result<(), DurabilityError> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// Replay the durability file into `log`, re-verifying each frame against the
/// device registry. Returns the number of ops appended. A missing file yields
/// zero. Ops whose device is unknown or whose signature fails are skipped (the
/// frame still counts as valid — the op stays on disk for a later replay that
/// does know the device).
///
/// A truncated or undecodable tail — a crash mid-write — ends the read AND is
/// truncated off the file, so the writer that reopens this file appends at a
/// clean frame boundary instead of burying valid frames behind a torn one.
pub fn replay_oplog_file(
    path: &Path,
    registry: &DeviceRegistry,
    log: &mut OpLog,
) -> Result<usize, DurabilityError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut appended = 0;
    // Byte offset of the end of the last structurally valid frame; everything
    // past it is a torn tail to cut off.
    let mut valid_end: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            // Clean end of file, or a torn length prefix from a crashed write.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut frame = vec![0u8; len];
        if reader.read_exact(&mut frame).is_err() {
            break; // truncated trailing frame
        }
        let op = match SignedOp::from_bytes(&frame) {
            Ok(op) => op,
            Err(_) => break, // corruption boundary: trust nothing past here
        };
        valid_end += 4 + len as u64;
        if let Some(key) = registry.key_for(&op.body.device) {
            if op.verify(key).is_ok() && log.append(op) {
                appended += 1;
            }
        }
    }
    if valid_end < file_len {
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(valid_end)?;
    }
    Ok(appended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::op::{ENVELOPE_VERSION, OpBody, StoreId};

    fn op(id: &DeviceIdentity, hlc: u64) -> SignedOp {
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(hlc),
            device: id.device_id(),
            store: StoreId::new("kv").unwrap(),
            payload: vec![hlc as u8],
        };
        SignedOp::seal(body, id).unwrap()
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let id = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 10)).unwrap();
        writer.append(&op(&id, 20)).unwrap();
        drop(writer);

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*id.verifying_key());
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 2);
        assert_eq!(log.len(), 2);
    }

    // Regression, codex phase-1 round 3: a mid-frame write failure must not
    // leave a torn frame that makes later valid frames unreachable on replay.
    // The failed append rolls the file back to the frame boundary, so the
    // retry frame is the next frame and replay recovers everything.
    #[test]
    fn mid_frame_failure_rolls_back_so_retry_frame_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let id = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 10)).unwrap();
        writer.fail_mid_append();
        assert!(writer.append(&op(&id, 20)).is_err());
        // Rolled back: retry succeeds and lands as a clean frame.
        writer.append(&op(&id, 20)).unwrap();
        drop(writer);

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*id.verifying_key());
        let mut log = OpLog::new();
        // Both ops are reachable; a torn frame would have stopped replay at 1.
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 2);
    }

    // Regression, codex phase-1 round 4: a torn tail left by a real crash must
    // be truncated off by replay, so a writer that reopens the file appends at
    // a clean boundary instead of burying its frames behind the tear.
    #[test]
    fn replay_truncates_crash_torn_tail_so_new_frames_are_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let id = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 10)).unwrap();
        drop(writer);
        // Simulate a crash mid-frame: a length prefix promising more bytes
        // than follow.
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&(1024u32).to_le_bytes()).unwrap();
            file.write_all(&[0xAB; 7]).unwrap();
        }

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*id.verifying_key());

        // Startup replay: reads the valid prefix and cuts the torn tail off.
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 1);

        // The reopened writer now appends at the clean boundary...
        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 20)).unwrap();
        drop(writer);

        // ...so the next replay reaches both ops.
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 2);
    }

    // Regression, codex phase-1 round 4 (companion): frames from a device the
    // registry does not know are skipped but must NOT count as corruption —
    // they stay on disk for a later replay that does know the device.
    #[test]
    fn unknown_device_frames_survive_replay_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let known = DeviceIdentity::generate();
        let unknown = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&unknown, 10)).unwrap();
        writer.append(&op(&known, 20)).unwrap();
        drop(writer);

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*known.verifying_key());
        let mut log = OpLog::new();
        // Only the known device's op lands, but the file is not truncated.
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 1);

        // Once the device is known (e.g. keys loaded from peers.bin), the
        // skipped frame is recovered from the same file.
        registry.insert_key(*unknown.verifying_key());
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 2);
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.bin");
        let registry = DeviceRegistry::new();
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 0);
    }

    #[test]
    fn truncated_trailing_frame_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let id = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 10)).unwrap();
        drop(writer);

        // Simulate a crash mid-write: a length prefix promising bytes never written.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&99u32.to_le_bytes()).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        drop(file);

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*id.verifying_key());
        let mut log = OpLog::new();
        // The one complete frame survives; the torn trailer is dropped.
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 1);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn unknown_device_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oplog.bin");
        let id = DeviceIdentity::generate();

        let mut writer = OplogWriter::open(&path).unwrap();
        writer.append(&op(&id, 10)).unwrap();
        drop(writer);

        // Registry does not know this device: the op cannot be verified, so skip it.
        let registry = DeviceRegistry::new();
        let mut log = OpLog::new();
        assert_eq!(replay_oplog_file(&path, &registry, &mut log).unwrap(), 0);
        assert_eq!(log.len(), 0);
    }
}
