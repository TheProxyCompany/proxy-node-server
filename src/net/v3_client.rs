//! Pull Protocol v3 client drain state machine, channel decoders, reset
//! validation, head-window preview, and store sweeps parameterized over
//! [`MeshPullSocket`].

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::client::HttpPullSource;
use super::socket::{MeshPullSocket, PullAdmission};
use super::v3_server::v3_needs_reset;
use super::{RelayCursorV2, decode_fixed_hex};
use crate::error::TransportError;
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::op::{OpId, OrderKey, SignedOp};
use crate::pull_v3::{
    PULL_V3_VERSION, PullPageV3, PullPhase, PullRequestV3, ResumeV3, V3_PAGE_LIMIT_MAX,
    sign_pull_request_v3, verify_pull_page_v3,
};

/// Poll-only fallback interval for a peer whose `/watch` errored.
pub const PULL_FALLBACK_INTERVAL: Duration = Duration::from_secs(10);

/// Backoff between `register_peer` attempts for an offline configured peer.
pub const REGISTER_RETRY_BACKOFF: Duration = Duration::from_secs(15);

/// How long a peer stays poll-only (or v2-only) before re-probing.
pub const WATCH_REPROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Cadence for rescanning the registry candidate set between feed notifications.
pub const DISCOVERY_RESCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Arrival gap beyond which a v3 drain runs a newest-first preview of the head window.
pub const NEWEST_FIRST_PREVIEW_GAP: u64 = V3_PAGE_LIMIT_MAX as u64;

/// Consecutive non-advancing v3 pages before failing the exchange.
pub const V3_NO_PROGRESS_LIMIT: u32 = 2;

/// Interval between claim-ignoring store sweeps on each link.
pub const TRELLIS_SWEEP_INTERVAL: Duration = Duration::from_secs(600);

/// Durable backbone position plus resume token compared between pages to
/// detect a non-advancing exchange.
pub type V3Progress = (u64, Option<(u8, u64, String, String)>);

/// What one v3 drain did, beyond the ops it applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3Outcome {
    Applied(usize),
    Unsupported,
    Warming,
}

/// Current Unix timestamp in milliseconds.
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Decode a 32-byte hex-encoded stream epoch.
pub fn decode_epoch(hex: &str) -> Option<[u8; 32]> {
    decode_fixed_hex::<32>(hex)
}

/// Decode a 72-byte hex-encoded [`OrderKey`].
pub fn decode_order_key(hex: &str) -> Option<OrderKey> {
    decode_fixed_hex::<72>(hex).map(|wire| OrderKey::from_wire(&wire))
}

/// Compute the starting sequence for a newest-first head-window preview.
/// Re-anchors at `head_seq - V3_PAGE_LIMIT_MAX` whenever `previous` is absent
/// or fell more than one full page behind `head_seq`.
pub fn preview_resume_after(previous: Option<u64>, head_seq: u64) -> u64 {
    let window_start = head_seq.saturating_sub(u64::from(V3_PAGE_LIMIT_MAX));
    previous
        .filter(|after| {
            *after <= head_seq && head_seq.saturating_sub(*after) <= u64::from(V3_PAGE_LIMIT_MAX)
        })
        .unwrap_or(window_start)
}

/// Build an inflated coverage map claiming `OrderKey::MAX` for each known
/// origin device so a preview request forces all arrivals onto Channel B.
pub fn inflated_claims<I: IntoIterator<Item = DeviceId>>(origins: I) -> BTreeMap<String, String> {
    origins
        .into_iter()
        .map(|origin| {
            let max_key = OrderKey {
                hlc: Hlc(u64::MAX),
                device: origin,
                op_id: OpId::from_bytes([0xff; 32]),
            };
            (origin.to_hex(), encode_hex(&max_key.to_wire()))
        })
        .collect()
}

/// Compute the progress tuple for stall detection across paged v3 responses.
pub fn v3_progress(relay_cursor: Option<RelayCursorV2>, resume: Option<&ResumeV3>) -> V3Progress {
    (
        relay_cursor.map(|cursor| cursor.after).unwrap_or(0),
        resume.map(|resume| {
            (
                match resume.phase {
                    PullPhase::Backfill => 0u8,
                    PullPhase::Keyed => 1u8,
                },
                resume.after_seq,
                resume.origin.clone(),
                resume.after_key.clone(),
            )
        }),
    )
}

/// Build a `reqwest::Client` configured for v3 page exchanges (5s connect
/// timeout, 60s request timeout, no redirects).
pub fn v3_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Base64-decode and deserialize one [`SignedOp`] entry from a [`PullPageV3`].
pub fn decode_page_op(encoded: &str, peer: &DeviceId) -> Result<SignedOp, String> {
    let bytes = BASE64.decode(encoded).map_err(|error| {
        format!(
            "v3 pull peer={} sent an undecodable entry: {error}",
            peer.to_hex()
        )
    })?;
    SignedOp::from_bytes(&bytes).map_err(|error| {
        format!(
            "v3 pull peer={} sent an invalid envelope: {error}",
            peer.to_hex()
        )
    })
}

/// Validate a reset [`PullPageV3`] against the [`PullRequestV3`] that elicited
/// it, returning the new [`RelayCursorV2`] `(response_epoch, page.floor)`.
pub fn validate_v3_reset(
    request: &PullRequestV3,
    page: &PullPageV3,
    response_epoch: [u8; 32],
) -> Result<RelayCursorV2, String> {
    if !page.reset {
        return Err("invalid v3 reset: response was not marked as a reset".to_string());
    }
    if page.floor > page.head_seq {
        return Err(format!(
            "invalid v3 reset: floor {} exceeds signed head {}",
            page.floor, page.head_seq
        ));
    }
    if !page.backfill.is_empty()
        || !page.keyed.is_empty()
        || page.next_relay_seq != 0
        || page.resume.is_some()
        || page.complete
        || page.snapshot_recommended
        || page.store.is_some()
    {
        return Err(
            "invalid v3 reset: reset page carried data, progress, or resume state".to_string(),
        );
    }

    let request_epoch =
        decode_epoch(&request.relay_epoch).ok_or_else(|| "invalid relay epoch".to_string())?;
    let response_state = crate::log::RelayStreamState {
        epoch: response_epoch,
        head: page.head_seq,
        floor: page.floor,
    };
    if !v3_needs_reset(request_epoch, request.relay_after, &response_state) {
        return Err(
            "invalid v3 reset: signed stream state does not invalidate the requested cursor"
                .to_string(),
        );
    }

    Ok(RelayCursorV2 {
        epoch: response_epoch,
        after: page.floor,
    })
}

/// Validate a v3 reset response and commit the replacement cursor through `socket`.
pub async fn persist_v3_reset<S>(
    socket: &S,
    peer: &DeviceId,
    request: &PullRequestV3,
    page: &PullPageV3,
    response_epoch: [u8; 32],
) -> Result<RelayCursorV2, S::Error>
where
    S: MeshPullSocket + Sync + ?Sized,
{
    let reset = validate_v3_reset(request, page, response_epoch).map_err(|msg| {
        if msg == "invalid relay epoch" {
            S::invalid_argument(msg)
        } else {
            S::protocol_error(msg)
        }
    })?;
    socket.commit_v3_reset(peer, reset).await?;
    Ok(reset)
}

/// Apply one verified [`PullPageV3`] through `socket`. Channel B advances the
/// durable relay cursor and folds `next_relay_seq`; Channel A advances one
/// coverage claim per origin run over its claim-safe prefix.
pub async fn apply_pull_page_v3<S>(
    socket: &S,
    peer: &DeviceId,
    cursor: &mut Option<RelayCursorV2>,
    page: &PullPageV3,
    skip_unattested: bool,
) -> Result<usize, S::Error>
where
    S: MeshPullSocket + Sync + ?Sized,
{
    let epoch = decode_epoch(&page.epoch)
        .ok_or_else(|| S::protocol_error("v3 pull page carries an invalid epoch"))?;
    let mut current = match *cursor {
        Some(current) if current.epoch == epoch => current,
        Some(_) => {
            return Err(S::protocol_error(format!(
                "v3 pull peer={} changed stream epoch without a reset",
                peer.to_hex()
            )));
        }
        None => RelayCursorV2 { epoch, after: 0 },
    };
    socket.commit_relay_cursor(peer, current).await?;
    *cursor = Some(current);

    let mut applied = 0usize;
    let mut backfill_seqs = Vec::with_capacity(page.backfill.len());
    let mut backfill_ops = Vec::with_capacity(page.backfill.len());
    let mut last_seq = current.after;
    for (seq, encoded) in &page.backfill {
        if *seq <= last_seq {
            return Err(S::protocol_error(format!(
                "v3 pull peer={} returned non-advancing sequence {seq} at or behind {}",
                peer.to_hex(),
                current.after
            )));
        }
        last_seq = *seq;
        backfill_seqs.push(*seq);
        backfill_ops.push(decode_page_op(encoded, peer).map_err(S::protocol_error)?);
    }

    let PullAdmission {
        admitted,
        error: admit_error,
        ..
    } = socket
        .admit_ops(
            peer,
            &backfill_ops,
            skip_unattested,
            true,
            |admitted_total, _| {
                if admitted_total > 0 {
                    current.after = backfill_seqs[admitted_total - 1];
                    *cursor = Some(current);
                    socket.save_relay_cursor(peer, current)?;
                }
                Ok(())
            },
        )
        .await?;
    applied += admitted;
    if let Some(error) = admit_error {
        return Err(error);
    }

    let next_cursor = RelayCursorV2 {
        epoch: current.epoch,
        after: current.after.max(page.next_relay_seq),
    };
    socket.commit_relay_cursor(peer, next_cursor).await?;
    *cursor = Some(next_cursor);

    let mut runs: Vec<(DeviceId, Vec<SignedOp>, Vec<OrderKey>)> = Vec::new();
    let mut last_key: Option<OrderKey> = None;
    for encoded in &page.keyed {
        let op = decode_page_op(encoded, peer).map_err(S::protocol_error)?;
        let key = op.order_key();
        let run_count = runs.len();
        match runs.last_mut() {
            Some((origin, ops, keys)) if *origin == key.device => {
                if last_key.is_some_and(|last| key <= last) {
                    return Err(S::protocol_error(format!(
                        "v3 pull peer={} returned a non-ascending keyed entry for origin {}",
                        peer.to_hex(),
                        origin.to_hex()
                    )));
                }
                ops.push(op);
                keys.push(key);
            }
            Some((origin, _, _)) => {
                if run_count > 1 && key.device < *origin {
                    return Err(S::protocol_error(format!(
                        "v3 pull peer={} returned keyed origins out of order",
                        peer.to_hex()
                    )));
                }
                runs.push((key.device, vec![op], vec![key]));
            }
            None => runs.push((key.device, vec![op], vec![key])),
        }
        last_key = Some(key);
    }

    for (origin, ops, keys) in &runs {
        let mut committed_claim_safe = 0usize;
        let PullAdmission {
            admitted,
            error: admit_error,
            ..
        } = socket
            .admit_ops(peer, ops, skip_unattested, true, |_, claim_safe_total| {
                if claim_safe_total > committed_claim_safe {
                    socket.advance_local_coverage(origin, keys[claim_safe_total - 1])?;
                    committed_claim_safe = claim_safe_total;
                }
                Ok(())
            })
            .await?;
        applied += admitted;
        if let Some(error) = admit_error {
            return Err(error);
        }
    }
    Ok(applied)
}

/// Fetch `peer`'s arrival stream after `after_seq` with inflated claims and
/// apply it through `socket` without advancing any durable cursor or claim.
pub async fn preview_head_window_v3<S>(
    socket: &S,
    source: &HttpPullSource,
    peer: &DeviceId,
    peer_sec1: &[u8; 33],
    relay_cursor: Option<RelayCursorV2>,
    after_seq: u64,
) -> Result<(usize, u64), S::Error>
where
    S: MeshPullSocket + Sync + ?Sized,
{
    let origins = socket.known_origins()?;
    let request = PullRequestV3 {
        version: PULL_V3_VERSION,
        coverage: inflated_claims(origins),
        relay_epoch: encode_hex(&relay_cursor.map(|c| c.epoch).unwrap_or([0u8; 32])),
        relay_after: relay_cursor.map(|c| c.after).unwrap_or(0),
        resume: Some(ResumeV3 {
            phase: PullPhase::Backfill,
            after_seq,
            origin: String::new(),
            after_key: String::new(),
        }),
        limit: V3_PAGE_LIMIT_MAX,
        audit: false,
        store: None,
        issued_at_ms: socket.now_ms(),
    };
    let page = source
        .pull_v3(
            &request,
            socket.local_identity(),
            socket.next_hlc(),
            peer,
            peer_sec1,
        )
        .await
        .map_err(|error| {
            S::protocol_error(format!(
                "v3 preview pull from peer {}: {error}",
                peer.to_hex()
            ))
        })?;
    if page.reset || page.snapshot_recommended {
        return Ok((0, after_seq));
    }
    let mut ops = Vec::with_capacity(page.backfill.len());
    for (_, encoded) in &page.backfill {
        ops.push(decode_page_op(encoded, peer).map_err(S::protocol_error)?);
    }
    let PullAdmission { admitted, .. } = socket
        .admit_ops(peer, &ops, false, false, |_, _| Ok(()))
        .await?;
    let next_seq = admitted
        .checked_sub(1)
        .and_then(|index| page.backfill.get(index))
        .map_or(after_seq, |(seq, _)| *seq);
    Ok((admitted, next_seq))
}

/// Page `peer`'s entire slice of `store` with claims ignored and apply it
/// through `socket` without advancing durable cursors or claims.
pub async fn sweep_store_v3<S>(
    socket: &S,
    source: &HttpPullSource,
    peer: &DeviceId,
    peer_sec1: &[u8; 33],
    relay_cursor: Option<RelayCursorV2>,
    store: &str,
) -> Result<usize, S::Error>
where
    S: MeshPullSocket + Sync + ?Sized,
{
    let mut applied = 0usize;
    let mut resume: Option<ResumeV3> = None;
    let mut last_resume: Option<(String, String)> = None;
    loop {
        let request = PullRequestV3 {
            version: PULL_V3_VERSION,
            coverage: BTreeMap::new(),
            relay_epoch: encode_hex(&relay_cursor.map(|c| c.epoch).unwrap_or([0u8; 32])),
            relay_after: relay_cursor.map(|c| c.after).unwrap_or(0),
            resume: resume.clone(),
            limit: V3_PAGE_LIMIT_MAX,
            audit: true,
            store: Some(store.to_string()),
            issued_at_ms: socket.now_ms(),
        };
        let envelope = sign_pull_request_v3(&request, socket.local_identity(), socket.next_hlc())
            .map_err(S::protocol_error)?;
        let (status, bytes) = source.pull_v3_bytes(envelope).await.map_err(|error| {
            S::protocol_error(format!(
                "v3 store sweep from peer {}: {error}",
                peer.to_hex()
            ))
        })?;
        if matches!(status, 404 | 405 | 503) {
            return Ok(applied);
        }
        if !(200..300).contains(&status) {
            return Err(S::protocol_error(format!(
                "peer {} refused the v3 store sweep (HTTP {status})",
                peer.to_hex()
            )));
        }
        let page = verify_pull_page_v3(&bytes, peer, peer_sec1).map_err(S::protocol_error)?;
        if page.store.as_deref() != Some(store) {
            return Ok(applied);
        }
        let mut ops = Vec::with_capacity(page.keyed.len());
        for encoded in &page.keyed {
            ops.push(decode_page_op(encoded, peer).map_err(S::protocol_error)?);
        }
        let PullAdmission {
            admitted,
            error: admit_error,
            ..
        } = socket
            .admit_ops(peer, &ops, true, true, |_, _| Ok(()))
            .await?;
        applied += admitted;
        if admit_error.is_some() || page.complete {
            return Ok(applied);
        }
        let position = page
            .resume
            .as_ref()
            .map(|r| (r.origin.clone(), r.after_key.clone()));
        if position == last_resume {
            return Err(S::protocol_error(format!(
                "v3 store sweep peer={} returned a non-advancing resume",
                peer.to_hex()
            )));
        }
        last_resume = position;
        resume = page.resume;
    }
}

/// Execute a complete v3 multi-page drain against `source` using `socket` for
/// coverage reads, op admission, cursor persistence, and head-window previews.
#[allow(clippy::too_many_arguments)]
pub async fn drain_v3_pages<S>(
    socket: &S,
    source: &HttpPullSource,
    peer: &DeviceId,
    peer_sec1: &[u8; 33],
    relay_cursor: &mut Option<RelayCursorV2>,
    audit: bool,
    skip_unattested: bool,
) -> Result<V3Outcome, S::Error>
where
    S: MeshPullSocket + Sync + ?Sized,
{
    let mut total = 0usize;
    let mut resume: Option<ResumeV3> = None;
    let mut reset_seen = false;
    let mut recommendation_overridden = false;
    let mut pages = 0u64;
    let mut stalled = 0u32;
    let mut last_progress: Option<V3Progress> = None;
    let mut last_preview: Option<Instant> = None;
    let mut preview_after: Option<u64> = None;
    let preview_due =
        |last: &Option<Instant>| last.is_none_or(|at| at.elapsed() > Duration::from_secs(10));

    loop {
        let coverage = socket.local_coverage()?;
        let request = PullRequestV3 {
            version: PULL_V3_VERSION,
            coverage: coverage.to_wire_map(),
            relay_epoch: encode_hex(&relay_cursor.map(|c| c.epoch).unwrap_or([0u8; 32])),
            relay_after: relay_cursor.map(|c| c.after).unwrap_or(0),
            resume: resume.clone(),
            limit: V3_PAGE_LIMIT_MAX,
            audit,
            store: None,
            issued_at_ms: socket.now_ms(),
        };
        let resumed = request.resume.is_some();
        let envelope = sign_pull_request_v3(&request, socket.local_identity(), socket.next_hlc())
            .map_err(S::protocol_error)?;
        let (status, bytes) = source.pull_v3_bytes(envelope).await.map_err(|error| {
            S::protocol_error(format!("v3 pull from peer {}: {error}", peer.to_hex()))
        })?;
        if status == 404 || status == 405 {
            return Ok(V3Outcome::Unsupported);
        }
        if status == 503 {
            return Ok(V3Outcome::Warming);
        }
        if !(200..300).contains(&status) {
            return Err(S::protocol_error(format!(
                "peer {} refused the v3 pull (HTTP {status}): {}",
                peer.to_hex(),
                String::from_utf8_lossy(&bytes).trim()
            )));
        }
        let page = verify_pull_page_v3(&bytes, peer, peer_sec1).map_err(S::protocol_error)?;
        let epoch = decode_epoch(&page.epoch).ok_or_else(|| {
            S::protocol_error(format!(
                "v3 pull peer={} returned an invalid stream epoch",
                peer.to_hex()
            ))
        })?;

        if page.snapshot_recommended {
            if recommendation_overridden {
                return Err(S::protocol_error(format!(
                    "v3 pull peer={} kept recommending a snapshot on resumed requests",
                    peer.to_hex()
                )));
            }
            recommendation_overridden = true;
            if preview_due(&last_preview) && page.head_seq > 0 {
                last_preview = Some(Instant::now());
                let after_seq = preview_resume_after(preview_after, page.head_seq);
                if let Ok((_applied, next_seq)) = preview_head_window_v3(
                    socket,
                    source,
                    peer,
                    peer_sec1,
                    *relay_cursor,
                    after_seq,
                )
                .await
                {
                    preview_after = Some(next_seq);
                }
            }
            resume = Some(ResumeV3 {
                phase: PullPhase::Backfill,
                after_seq: relay_cursor.map(|c| c.after).unwrap_or(0),
                origin: String::new(),
                after_key: String::new(),
            });
            continue;
        }
        if page.reset {
            if reset_seen {
                return Err(S::protocol_error(format!(
                    "v3 pull peer={} repeated its stream reset",
                    peer.to_hex()
                )));
            }
            reset_seen = true;
            let reset = persist_v3_reset(socket, peer, &request, &page, epoch).await?;
            *relay_cursor = Some(reset);
            resume = None;
            continue;
        }

        total += apply_pull_page_v3(socket, peer, relay_cursor, &page, skip_unattested).await?;
        pages += 1;
        socket.on_v3_page_applied(peer, &page, pages, total);

        if preview_due(&last_preview) && !page.complete {
            last_preview = Some(Instant::now());
            let behind = page
                .head_seq
                .saturating_sub(relay_cursor.map(|c| c.after).unwrap_or(0));
            if behind > NEWEST_FIRST_PREVIEW_GAP {
                let after_seq = preview_resume_after(preview_after, page.head_seq);
                if let Ok((_applied, next_seq)) = preview_head_window_v3(
                    socket,
                    source,
                    peer,
                    peer_sec1,
                    *relay_cursor,
                    after_seq,
                )
                .await
                {
                    preview_after = Some(next_seq);
                }
            }
        }

        if page.complete {
            if !resumed {
                return Ok(V3Outcome::Applied(total));
            }
            resume = None;
            continue;
        }
        resume = page.resume;

        let progress = v3_progress(*relay_cursor, resume.as_ref());
        if last_progress.as_ref() == Some(&progress) {
            stalled += 1;
            if stalled >= V3_NO_PROGRESS_LIMIT {
                return Err(S::protocol_error(format!(
                    "v3 pull peer={} returned {stalled} pages without advancing",
                    peer.to_hex()
                )));
            }
        } else {
            stalled = 0;
        }
        last_progress = Some(progress);
    }
}

impl HttpPullSource {
    /// Seal `request` under `local_identity` at `hlc`, POST it to [`crate::pull_v3::PULL_PATH`],
    /// and verify the returned [`PullPageV3`] envelope against `expected_peer`
    /// and `expected_peer_key`.
    pub async fn pull_v3(
        &self,
        request: &PullRequestV3,
        local_identity: &DeviceIdentity,
        hlc: Hlc,
        expected_peer: &DeviceId,
        expected_peer_key: &[u8; 33],
    ) -> Result<PullPageV3, TransportError> {
        let signed_request =
            sign_pull_request_v3(request, local_identity, hlc).map_err(TransportError::Wire)?;
        let (status, body) = self.pull_v3_bytes(signed_request).await?;
        if matches!(status, 404 | 405 | 501) {
            return Err(TransportError::RelayV2Unsupported { status });
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http(format!("status {status}")));
        }
        verify_pull_page_v3(&body, expected_peer, expected_peer_key).map_err(|reason| {
            TransportError::Verify {
                device: expected_peer.to_hex(),
                reason,
            }
        })
    }
}
