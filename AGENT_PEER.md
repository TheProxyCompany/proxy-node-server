# Agent peer RPC

Signed request/reply RPC between devices that are *already trusted* in the
Proxy device mesh. Grand Central attaches to a durable native agent on its
assigned always-on device through the node's existing HTTP listener: no SSH,
no parallel listener, no second trust database, and no owner credential ever
rides in a request.

Trust is exactly the injected `DeviceBook`. A sender whose verifying key is
absent from the book is unknown; a network OAuth/PACT client has no device key
in the book at all, so this transport cannot turn one into an owner device.

## Wire shape

One route, merged into the node's existing axum router:

    POST /peer/agents        content-type: application/octet-stream

Body and response are postcard frames of the tuple `(SignedOp bytes, payload
bytes)` where payload is `RequestPayload` on the wire up and `ReplyPayload` on
the wire down. The `SignedOp` is the crate's existing P-256 envelope
(`src/op.rs`): the same parsing, malleability and content-addressing rules
apply unchanged. Envelopes use dedicated store ids and are **never appended to
any replication op-log** — they are transport frames, not replicated state.

    REQUEST_STORE = "agent-peer.request.v1"
    REPLY_STORE   = "agent-peer.request.v1.reply"

Envelope `body.payload` is the 32-byte SHA-256 of
`"proxy-node-server/agent-peer/payload/v1\0" ‖ postcard(payload)`, so the
sender's envelope signature commits to exactly the canonical signed payload.
`body.device` is always the signer (sealing stamps it), so the *expected
recipient* and the *freshness timestamp* ride inside the signed payload:

    RequestPayload { v: 1, target: DeviceId, timestamp_ms: u64, command }
    ReplyPayload   { v: 1, request_id: OpId, requester: DeviceId,
                     error: Option<String>, payload: Option<Value-as-JSON-string> }

A reply's content id covers `request_id` and `requester`, so a reply signature
is bound to exactly one request and one requester, and is only acceptable from
the expected target. Unsigned status JSON is never trusted by the client.

Postcard is non-self-describing, so the signed core uses no `serde(rename)`
on fields, no internally/adjacently tagged enums, no arbitrary `Value` slots
and no `skip_serializing_if` fields — every one of those fails postcard
decoding. (`PeerAgentInput` exists precisely to give `AgentInput` a canonical
wire form; convert with `From`.)

## Server

    let server = PeerServer::new(
        identity,          // Arc<DeviceIdentity>: this device
        devices,           // impl DeviceBook: the trusted set (same book as the mesh)
        handler,           // Arc<dyn PeerHandler>: app policy, resolves definitions
        replay_dir,        // private durable replay directory (0700, fsynced, leased)
    )?;
    router = router.merge(server.router());

Before the handler can run, the server enforces, in order:

1. Envelope parses; store is `agent-peer.request.v1`; `payload.v == 1`.
2. `payload.target == identity.device_id()` — the request is for *this* node.
3. `|now − payload.timestamp_ms| ≤ 120 s` — bounded clock skew.
4. The signer's key resolves from the injected `DeviceBook` and derives
   `body.device`; unknown/revoked senders never proceed.
5. Envelope signature verifies low-S under that key and the envelope's
   committed digest equals the received payload's digest (no substitution).
6. `command.validate()` — exact agent id shape, bounded input, bounded events
   limit, definition digest self-consistent.
7. Durable replay (below). Only then does the handler run.

Replies go through the same checks in mirror image, sealed under the server's
identity in `agent-peer.request.v1.reply`.

### Durable replay

One file per request id under the replay directory, written as pending
**before any handler effect**, fsynced (file and directory) before the handler
runs, and replaced with the fully-signed response frame after. Within one
process, the request id is also claimed exclusively for the whole
check→admit→handle→complete sequence, so two concurrent deliveries of
identical bytes cannot both pass the durable lookup:

- **Same signed bytes arrive again, completed record exists** → the cached
  reply bytes are returned; the handler does not run a second time. This holds
  across server restarts: the store is durable state, not a cache in RAM.
- **Same signed bytes arrive, record still Pending** (crash after admit,
  before complete) → `409 Conflict` / `PeerError::OutcomeUnknown`. An effect
  the transport cannot prove completed is never silently repeated.
- **Same signed bytes arrive concurrently, record not yet written** → the
  losing delivery is refused with the same `409 Conflict` outcome-unknown
  result rather than being admitted or dispatched; the claim is released when
  the winning request writes its record (or unwinds on panic, leaving a
  durable Pending).
- A `Submit` retried through a **new** envelope necessarily has a new request
  id; the runtime's own stable `input.id` remains the dedupe key for that
  second attempt, exactly as it does between two local submissions.

## Client

    let endpoint = PeerEndpoint::new("https://proxy-terminal-1.example")?;
    let client = PeerClient::new(identity, devices, target_device_id, endpoint)?;
    let reply: serde_json::Value = client.command(PeerCommand::Status { agent: "jarvis".into() }).await?;

`PeerEndpoint::new` rejects URL credentials, fragments and non-HTTPS schemes;
loopback HTTP (`127.0.0.1`, `::1`, `localhost`) is allowed for local tests.
Redirects are disabled; request timeout is 75 s; response bodies are capped at
4 MiB *while streaming* (a declared `Content-Length` over the cap is rejected
early and an over-cap chunk is rejected before it is buffered), so a
compromised target cannot make the client buffer an unbounded body. The client verifies, before surfacing anything, that the reply is
well-formed, signed by the *expected target*, bound to *this request's id*,
and addressed to *this requester*: forged, tampered, wrong-peer or
wrong-request replies are rejected as `Unauthenticated`, and an unsigned error
page is a transport failure, never a payload.

## Command surface

Typed, closed set (`PeerCommand`): `Ensure { agent, definitions }`,
`Open { agent }`, `Status { agent }`, `Submit { agent, input }`,
`Events { agent, after_sequence, limit ≤ 256 }`, `Abort { agent }`. Every
variant names exactly one agent id — a caller can submit only to the exact
requested agent, and every reply/event/status value is correlated with that
id by the server's echo. There is no remote executable path, command line,
arbitrary host filesystem path, environment map, or provider/MCP secret
anywhere in the surface, and no variant can be used as a proxy to a different
agent than the one it names.

`DefinitionBundle` is bounded portable data: ≤ 64 files, each path ≤ 256
bytes, each file ≤ 256 KiB, ≤ 1 MiB total. Paths must be unique, relative and
clean — no absolute paths, `.`/`..` components, empty segments, backslashes,
or control characters (which also excludes NUL and symlink-style tricks).
`DefinitionBundle::seal` stamps a length-prefixed SHA-256 digest over
path-sorted `(path, content)` pairs; any path or content change changes the
digest. `expected` is a **compare-and-set guard only**: the receiving app's
handler parses the files through its own typed Rust library and decides
whether to install, and must refuse (`PeerError::Divergent`) rather than
overwrite when its current digest differs from `expected`. A digest match
never grants authority by itself.

## Migration is not represented

The shipping runtime has no atomic quiesce/admission fence, so no live
handoff or state-copy command exists here. A future handoff command must go
through an injected handler that proves admission is fenced, pending work is
drained and a durable checkpoint is ready, and until then must return
`PeerError::Unsupported`. An ordinary idle status or stopped process is not
proof of safe migration. First placement and attachment (`Ensure`/`Open`)
work without any of that.

## Proof scope and limits

`cargo test --all-features --test agent_peer` boots two independently keyed
loopback servers and an effect-counting fixture handler and verifies the real
signed round trip: accepted submit/open/status/events with exact-identity
echoes; byte-identical replay returning the cached signed reply with no second
effect, including across a server reopen; 64 concurrent deliveries of the same
signed bytes producing exactly one effect; unknown/forged/tampered/stale and
wrong-target requests never reaching the handler (counter stays zero); a
crash-pending replay returning 409 with no repeat effect; wrong-peer,
tampered (payload substituted under a valid target signature) and
wrong-request-id signed replies all rejected client-side; traversal-bearing,
oversized and undigested definitions rejected; an over-limit reply rejected
while streaming; and the over-limit events request refused before dispatch. These are protocol guarantees over fixtures — not evidence of real
model execution, guest provisioning, or any installed app behavior.

Known limits: replay files grow unbounded with request volume (an
integration-side retention job can fsck them safely since names are content
addresses); freshness uses `SystemTime` on both ends, so the 120 s window
assumes mesh devices keep ordinary NTP discipline; `409` on a pending replay
means a human or the caller's retry policy decides — the transport
deliberately does not.
