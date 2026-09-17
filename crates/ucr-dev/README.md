# UCR Dev Mode

Development-only local UCR host for the Phase-40 developer-first proof.

```bash
cargo run -p ucr-dev -- dev --check
cargo run -p ucr-dev -- dev --bind 127.0.0.1:50051
cargo run -p ucr-dev -- dev --simulate offline --check
```

The environment provides seeded local/mock-peer Identity+Device state, memory test storage, authenticated Service Principal access, a test transport, debug events, diagnostics and a loopback public API. `--check` executes real public Identity, Conversation, Message, Group and Call operations and the sandbox fault matrix.

The server refuses non-loopback binds. Authentication/permissions/quotas stay enabled. State and printed credentials are ephemeral development material. This crate is not a Production node, persistent deployment, discovery/Relay service or permission bypass.
