#![forbid(unsafe_code)]

// Compile-only browser compatibility sentinel.
//
// The direct getrandom dependency enables the official wasm_js backend in this isolated
// dependency graph. Referencing a public ucr-crypto item ensures the canonical crypto crate is
// actually built for wasm32-unknown-unknown instead of merely resolving dependencies.
pub use ucr_crypto::GroupMediaEpochSecret;

pub fn browser_crypto_compile_sentinel() -> &'static str {
    "ucr.crypto.browser-wasm.v1"
}
