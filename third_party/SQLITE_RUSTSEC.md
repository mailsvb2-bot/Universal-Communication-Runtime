# SQLite CVE-2026-119375 compatibility patches

Source packages copied from the crates.io release archives without replacing
their Rust implementation or schema migrations:
- openmls_sqlite_storage 0.3.0, OpenMLS authors (MIT license)
- refinery-core 0.9.2, refinery authors (MIT license)

Local changes:
1. openmls_sqlite_storage Cargo.toml: rusqlite 0.37 -> 0.41.1
2. refinery-core Cargo.toml: extend supported rusqlite upper version from
   <= 0.39 to <= 0.41.
3. Root Cargo.toml uses [patch.crates-io] for these exact two packages,
   because published OpenMLS storage 0.3.0 still requests rusqlite 0.37.
4. UCR's three direct rusqlite dependencies are pinned to 0.41.1,
   bundling patched SQLite through libsqlite3-sys 0.39.1.

Keep vendoring narrowly scoped; remove the two patches when matching upstream
releases support rusqlite 0.41.1. Do not modify migrations or silence RustSec.
