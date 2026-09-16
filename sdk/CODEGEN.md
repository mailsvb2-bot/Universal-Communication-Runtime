# Public SDK code generation

All language SDKs compile their wire types and service stubs from the checked-in `proto/ucr/v1/*.proto` files.
Generated files are derivative artifacts and must not be edited as protocol source.

The generated package/service names stay exactly under `ucr.v1`.
The external-consumer SDK surface exposes generated clients for `IntegrationService`, `EventService` and `CallService`.
Other public protobuf services may also be generated as the contract grows; language helpers must not reinterpret their messages.

## Required generator behavior

1. Include `proto` as the protobuf import root.
2. Generate message types from the complete `ucr/v1` package dependency graph.
3. Generate client stubs; SDK packages do not generate or expose a UCR server implementation as convenience logic.
4. Preserve unknown protobuf fields according to the selected language runtime where supported.
5. Attach Service Principal credentials only as the two binary metadata keys in `contract.json`.
6. Never inject credentials into protobuf request bodies.
7. Do not add automatic application-operation retries in generated wrappers.
8. Treat Event cursor bytes as opaque.

Rust code generation is executable repository evidence in `crates/ucr-sdk/build.rs`.
Python, TypeScript, Kotlin and Swift package/release automation must use the same schema root and contract manifest.
Exact external generator/plugin pinning and signed registry publishing belong to Phase 44 supply-chain hardening;
Phase 39 does not claim public registry artifacts.
