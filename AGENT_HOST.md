# Durable agent host

Enable the `agent-host` feature to put persistent agent processes behind the
node's existing HTTP listener. Grand Central resolves definitions, equipment and
credentials into `AgentSpec`; HTTP callers cannot register commands or paths.
The runtime executable receives `--rpc --agent … --state … --workspace …` and
`PROXY_AGENT_SEAT`. A provisioned Cua binding, when present, is passed separately
as `PROXY_AGENT_SPACE`. That binding is metadata, not virtualization: the app
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
An optional `PROXY_AGENT_HERDR_RESUME_ARGV` must attach to the existing host,
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
