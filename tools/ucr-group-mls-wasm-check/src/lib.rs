#![forbid(unsafe_code)]

// Compile-only browser compatibility sentinel.
//
// Disabling default features removes the native SQLite adapter while still compiling the canonical
// OpenMLS/RFC 9420 core used to create/join/process endpoint group state and derive media secrets.
// This is a build boundary only; durable browser persistence is a later endpoint-adapter concern.
pub use ucr_group_mls::{GROUP_MEDIA_EXPORT_LABEL, MLS_CIPHERSUITE, MlsGroupState, UcrOpenMlsProvider};

pub fn browser_group_mls_compile_sentinel() -> &'static str {
    GROUP_MEDIA_EXPORT_LABEL
}
