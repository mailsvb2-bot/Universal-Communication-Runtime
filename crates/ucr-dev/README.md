# UCR Dev Mode

Development-only local UCR host for the Phase-40 developer-first proof.

```bash
cargo run -p ucr-dev -- dev --check
cargo run -p ucr-dev -- dev --bind 127.0.0.1:50051
cargo run -p ucr-dev -- dev --simulate offline --check
```

The environment provides seeded local/mock-peer Identity+Device state, an automatically created ephemeral SQLite test store, authenticated Service Principal access, a test transport, debug events, diagnostics and a loopback public API. `--check` executes real public Identity, Conversation, Message, Group and Call operations plus the Universal Conference integration path: idempotent conference create, participant/device preparation, runtime materialization, lifecycle transition, signed join grant, Realtime join/leave and attendance Event projection.

The server refuses non-loopback binds. Authentication/permissions/quotas stay enabled. State and printed credentials are ephemeral development material. This crate is not a Production node, persistent deployment, discovery/Relay service or permission bypass.


## Docker package

From the repository root:

```bash
docker compose up ucr
```

This keeps `ucr dev` itself loopback-only and exposes its raw gRPC bytes through a dev-only
forwarder mapped to host `127.0.0.1:50051`. The same container serves the reference browser client
on `http://127.0.0.1:8080/`, a bounded webhook receiver on
`http://127.0.0.1:8090/`, and a local coturn instance on port `3478`.
The container logs print ephemeral Service Credential material plus short-lived TURN REST test
credentials.

The TURN secret, browser hosting and webhook receiver are developer conveniences only. They are not
Production secret management, public ingress, durable deployment or evidence that a browser may
bypass the signed `#ucr_join` grant.
