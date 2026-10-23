# Durable agent host

Enable the `agent-host` feature to put persistent agent processes behind the
node's existing HTTP listener. Grand Central resolves definitions, equipment and
credentials into `AgentSpec`; HTTP callers cannot register commands or paths.
The runtime executable receives `--rpc --agent … --state … --workspace …` and
`PROXY_HARNESS_SEAT`. A provisioned Cua binding, when present, is passed separately
as `PROXY_HARNESS_SPACE`. That binding is metadata, not virtualization: the app
must launch into the actual guest and supply a computer MCP scoped to it.

`AgentHost::open` takes an exclusive lease on its private state directory.
`register`, `ensure_started`, `submit`, `status`, `subscribe`, `abort` and
`shutdown` provide the process lifecycle. Each registered ID has one process,
independent of attached HTTP clients. An idle configuration change waits for its
old process to stop; a busy change is refused. Unexpected exits are retried with
bounded backoff. The runtime owns recovery of accepted inputs and effects.

Submission succeeds only after a runtime `accepted` event with `durable: true`
has also reached the host journal. Timeout means acceptance is unknown: retry
the same input ID. Readers use the durable event cursor and SSE `Last-Event-ID`;
closing a reader does not close the runtime's input pipe. No tool execution is
inferred from a pipe write, process exit or status badge.

Merge `agent_host::http::router` into the existing server, supplying an authority
that checks the current OAuth/participant grant for the exact agent and operation.
It exposes `/client/agents/{agent}/{input,status,events,abort}` and `/{agent}`.
The events stream rechecks authority, and remote input is labeled `address-client`.

## PACT and Herdr

`pact_server::router` supplies public cards, JWKS, and A2A 1.0 HTTP+JSON operations
for explicitly published agents. Its `PactAuthority` must validate the PA JWT and
the application's current exact-agent consent. A signature alone is not consent.
Identity verification supports ES256 and RS256 against registered keys, exact
issuer/audience and the PACT time window. Contexts are bound to issuer, opaque
subject and agent; stored replies are idempotent, including across router
restart. Protocol reply work survives an HTTP disconnect. The application must
configure trusted issuer/key registration and provider-assigned opaque audiences;
none are inferred from a card URL or speaker identity.

The PACT client discovers the matching A2A interface, sends signed identity, and
supports OAuth device authorization plus signed receipt verification. Login
remains on the Brand's page. The inbound router implements the Identity path and
does not advertise optional Delegated authority. Provider registration and
consent UI belong to the application. Upstream source: <https://openpactprotocol.org/spec.md>.
Sierra/Meta Personal Agent Protocol is distinct; no invented PAP wire format is
advertised by this module.

Herdr integration is opt-in through `HERDR_ENV`, `HERDR_BIN_PATH`,
`HERDR_SOCKET_PATH` and `HERDR_PANE_ID`. The bridge uses the documented
`pane report-agent` / `release-agent` CLI with monotonically increasing sequence
numbers. Its latest-state background reporter cannot block runtime acceptance.
An optional `PROXY_HARNESS_HERDR_RESUME_ARGV` must attach to the existing host,
not launch a second root. Upstream: <https://herdr.dev/docs/add-herdr-support/>.

## Verification

`cargo clippy --all-targets --features agent-host -- -D warnings` and
`cargo test --all-features` pass. The host tests run actual isolated subprocesses
and HTTP listeners; they cover disconnect survival, crash recovery, busy loadout
changes, exclusive ownership, journal replay, exact-agent HTTP grants, PACT
cryptography, principal-bound contexts and reply idempotency. The subprocess is
a protocol fixture, not evidence of live model or installed app behavior.

An opt-in test additionally exercises the Rust bridge against official Herdr
0.9.3 in an explicitly created named headless session. On Terminal 1 it observed
working, blocked and idle through CLI readback, then confirmed release. It needs
`PROXY_TEST_HERDR_BIN`, `PROXY_TEST_HERDR_SOCKET`, and `PROXY_TEST_HERDR_PANE`:

```sh
cargo test --features agent-host --test agent_host herdr_live -- --ignored --nocapture
```

Application OAuth/PACT mounting, real model execution, guest provisioning and
installed-preview evidence are separate integration gates.

### Local Cua Spaces

`agent_host::space::CuaSpaceManager` provisions only local desktops on the
already-selected trusted Proxy device. The application supplies its private runtime data root and an installed absolute
CLI path. On macOS, the physically short, persistent engine home is
`/Users/Shared/.pxc-<uid>/runtime`, owned by this OS user with mode 0700 and a
Proxy ownership marker. Lima canonicalizes paths, so a symlink from `/tmp` to a
long profile does not solve its Unix-socket limit. Each profile keeps its own
`runtime-home.json` reference, sandbox registry and agent ownership records under
its selected data root; a persistent random namespace makes equal agent ids
use different desktops in different profiles. Profiles share only the Proxy-owned
local engine so Docker allocates distinct ports, and a filesystem lock serializes
provisioning across app processes. No existing `~/.cua`, Docker or Colima setup is
adopted. VM disks and guest artifacts remain in that persistent engine home;
profile deletion does not silently erase them.
`ensure_agent_space(agent_id, SpaceResources::default())` creates a Linux
container desktop in Cua's managed local Linux VM, or resumes that same owned
guest after a restart. Stop/start use Cua
`spaces stop` and `spaces start`, retaining guest files. `MacosVm` selects the local Lume backend. Ownership is
fsynced before creation, unknown pre-existing guests are never adopted, and an
exclusive manager lease serializes creation. The returned binding is checked
against the live local registry, ready state, actual isolation kind, and
loopback service endpoint. Workspace files live in the guest's own
`$HOME/ProxyWorkspace`; no host folder is mounted by this module. A container's
`disk_gb` must be zero because its engine controls storage; VM disk size is an
explicit request. There is no implicit guest deletion or cloud fallback.

The returned `CuaMcpLaunch` is for a trusted adapter only. **Do not expose the
raw CLI helper to an agent:** Cua's `--sandbox` selects a default, and an MCP
caller could otherwise override it. Grand Central's `computer::space` adapter
registers that launch against the authenticated agent, filters the tool names,
rejects target overrides, and injects the owned Space on every request. It
serializes screenshot-coordinate state and revocation, never falls back to the
host desktop, and never blindly repeats an ambiguous tool effect. A child with
computer authority must receive a separately allocated/bound guest. Parent
Space inheritance is not a child allocation.

Space metadata alone is not process isolation. Native shell, file, and process
tools must use the bound guest routes; a native host process cannot gain guest
isolation by setting `PROXY_HARNESS_SPACE`. Direct human screen observation and
an agent's guest computer actions remain separate capabilities.

For a reproducible macOS arm64 helper installation, run
`scripts/install-cua-helper.sh /absolute/Proxy-owned/helper/directory`. It
installs Cua CLI 0.4.1 from its fixed release URL only after verifying SHA-256
and vendor code signing, with a receipt and MIT notice. Packaging can use this
directory or bundle the verified helper under `Contents/Helpers`. Sign nested
executables before signing the enclosing app and include `licenses/CUA-MIT.txt`
in third-party notices. The helper only links system frameworks. Its runtime
assets belong in the private `CUA_HOME`, not the application bundle; test data
under a developer's temporary directory is not a shipping dependency.

The core CLI/SDK, Cua Driver, and Lume are MIT at pinned source commit
`ed22ad958a5ab6d764c98261b24d65f80f3a6f95`. The independently installed
`cua-spacesd` service and Cua Spaces app/streaming extensions are FSL-1.1-MIT.
This adapter does not vendor their source or relabel them as MIT. See upstream
[license boundaries](https://github.com/trycua/cua/blob/ed22ad958a5ab6d764c98261b24d65f80f3a6f95/LICENSING.md).

The `provision_agent_space` example exercises the real CLI and checks that
repeated provisioning resumes the same owned guest. Grand Central's ignored
`live_owned_guest_is_scoped_and_revocable` test accepts its JSON via
`PROXY_CUA_PROOF_JSON` and verifies actual guest shell/files, a native GUI
application and screenshot, target-override rejection, and revocation. It
requires an explicitly supplied test guest and never opens a browser or the
user's host desktop.
