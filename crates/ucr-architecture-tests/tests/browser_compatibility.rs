use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn browser_compatibility_matrix_runs_real_desktop_and_simulator_backed_mobile_browsers() {
    let workflow = read(".github/workflows/browser-compatibility.yml");
    let probe = read("tools/browser_compatibility_probe.py");
    let mobile_probe = read("tools/mobile_browser_compatibility_probe.py");
    let mobile_probe_js = read("crates/ucr-realtime-web/static/mobile-browser-probe.js");
    let client = read("crates/ucr-realtime-web/static/client.html");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let universal = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let spec = read("spec/browser-compatibility.md");

    for browser in ["chrome", "edge", "firefox", "safari"] {
        assert!(
            workflow.contains(&format!("browser: {browser}")),
            "missing desktop browser matrix row {browser}"
        );
    }
    assert!(workflow.contains("ubuntu-24.04"));
    assert!(workflow.contains("macos-15"));
    assert!(workflow.contains("safaridriver --enable"));
    assert!(workflow.contains("browser_compatibility_probe.py"));
    assert!(workflow.contains("wasm-bindgen-cli --version 0.2.128 --locked"));
    assert!(workflow.contains("--manifest-path crates/ucr-endpoint-wasm/Cargo.toml"));
    assert!(workflow.contains("--target web"));
    assert!(workflow.contains("--out-name ucr_endpoint_wasm"));
    assert!(workflow.contains("upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"));
    assert!(workflow.contains("name: mobile-android-chrome"));
    assert!(workflow.contains("google_apis_playstore;x86_64"));
    assert!(workflow.contains("pm path com.android.chrome"));
    assert!(workflow.contains("adb reverse tcp:8765 tcp:8765"));
    assert!(workflow.contains("name: mobile-ios-safari"));
    assert!(workflow.contains("xcrun simctl openurl"));
    assert!(workflow.contains("mobile_browser_compatibility_probe.py"));

    for invariant in [
        "real-desktop-browser-webdriver-smoke",
        "rtcPeerConnection",
        "restartIceFunction",
        "applyMediaPolicyFunction",
        "getUserMedia",
        "getDisplayMedia",
        "cryptoSubtle",
        "secureContext",
        "endpointWasmLoader",
        "endpointWasmExecution",
        "keyPackageBytes",
        "preJoinEpochRejected",
    ] {
        assert!(
            probe.contains(invariant),
            "missing browser probe invariant {invariant}"
        );
    }

    assert!(client.contains("ENDPOINT_WASM_CONTRACT_VERSION=\"ucr.endpoint-wasm.v1\""));
    assert!(client.contains("mobile-browser-probe.js"));
    assert!(client.contains("import(ENDPOINT_WASM_MODULE_URL)"));
    assert!(client.contains("module.endpoint_wasm_contract_version()"));
    assert!(client.contains("typeof module.EndpointMlsState!==\"function\""));
    assert!(client.contains("/v1/realtime/mls-context"));
    assert!(client.contains("/v1/realtime/mls-key-package"));
    assert!(client.contains("endpoint_state_mode"));
    assert!(client.contains("legacy_server_owned"));
    assert!(client.contains(
        "Endpoint-owned MLS state is already admitted but its sealed local snapshot is missing"
    ));
    assert!(client.contains("state.join_from_welcome("));
    assert!(client.contains("module.EndpointMlsState.restore("));
    assert!(client.contains("endpointApplyBootstrapCommits(restored,bootstrap,index)"));
    assert!(realtime.contains("register_endpoint_mls_key_package"));
    assert!(realtime.contains("mls_admission_context"));
    assert!(realtime.contains("with_mls_admission_store"));
    assert!(realtime.contains("RealtimeMlsEndpointStateMode::Register"));
    assert!(realtime.contains("RealtimeMlsEndpointStateMode::Restore"));
    assert!(realtime.contains("RealtimeMlsEndpointStateMode::LegacyServerOwned"));
    assert!(
        !universal.contains("create_mls_device_key_package(&owner.scope, &participant.device_id)"),
        "Universal Conference must not create participant MLS KeyPackages server-side"
    );

    for invariant in [
        "android-chrome",
        "ios-safari",
        "real-android-emulator-chrome-self-probe",
        "real-ios-simulator-safari-self-probe",
        "desktop_user_agent_emulation",
    ] {
        assert!(
            mobile_probe.contains(invariant),
            "missing mobile host probe invariant {invariant}"
        );
    }
    for invariant in [
        "ucr.mobile-browser-probe.v1",
        "browserIdentityMatches",
        "endpointWasmExecution",
        "endpointStatePersistence",
        "touchCapable",
    ] {
        assert!(
            mobile_probe_js.contains(invariant),
            "missing mobile browser self-probe invariant {invariant}"
        );
    }

    assert!(spec.contains("Android Chrome"));
    assert!(spec.contains("iOS Safari"));
    assert!(spec.contains("simulator/emulator-backed mobile browsers"));
    assert!(spec.contains("**not** accepted as production evidence"));
    assert!(spec.contains("does not by itself prove TURN reachability"));
}
