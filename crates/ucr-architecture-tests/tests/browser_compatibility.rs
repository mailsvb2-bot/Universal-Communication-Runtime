use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn assert_browser_workflow(workflow: &str) {
    for browser in ["chrome", "edge", "firefox", "safari"] {
        assert!(
            workflow.contains(&format!("browser: {browser}")),
            "missing desktop browser matrix row {browser}"
        );
    }
    for invariant in [
        "ubuntu-24.04",
        "macos-15",
        "macos-15-intel",
        "safaridriver --enable",
        "browser_compatibility_probe.py",
        "wasm-bindgen-cli --version 0.2.128 --locked",
        "--manifest-path crates/ucr-endpoint-wasm/Cargo.toml",
        "--target web",
        "--out-name ucr_endpoint_wasm",
        "upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "name: mobile-android-chrome",
        "google_apis_playstore;x86_64",
        "pm path com.android.chrome",
        "adb reverse tcp:8765 tcp:8765",
        "android_chrome_probe_runner.py",
        "--navigation-attempts 4",
        "--evidence-wait-seconds 40",
        "name: mobile-ios-safari",
        "ios-safari-attempts",
        "macos-15-intel",
        "DEVELOPER_DIR: /Applications/Xcode_16.4.app/Contents/Developer",
        "Verify pinned Xcode",
        "download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "real-ios-simulator-safari-self-probe",
        "no successful real iOS Safari simulator evidence",
        "ios_safari_probe_runner.py",
        "android_chrome_probe_runner.py",
    ] {
        assert!(
            workflow.contains(invariant),
            "missing browser workflow invariant {invariant}"
        );
    }
}

fn assert_desktop_probe(probe: &str) {
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
}

fn assert_mobile_probe(host_probe: &str, browser_probe: &str) {
    for invariant in [
        "android-chrome",
        "ios-safari",
        "real-android-emulator-chrome-self-probe",
        "real-ios-simulator-safari-self-probe",
        "desktop_user_agent_emulation",
    ] {
        assert!(
            host_probe.contains(invariant),
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
            browser_probe.contains(invariant),
            "missing mobile browser self-probe invariant {invariant}"
        );
    }
}

fn assert_endpoint_mls_binding(client: &str, realtime: &str, universal: &str) {
    for invariant in [
        "ENDPOINT_WASM_CONTRACT_VERSION=\"ucr.endpoint-wasm.v1\"",
        "mobile-browser-probe.js",
        "import(ENDPOINT_WASM_MODULE_URL)",
        "module.endpoint_wasm_contract_version()",
        "typeof module.EndpointMlsState!==\"function\"",
        "/v1/realtime/mls-context",
        "/v1/realtime/mls-key-package",
        "endpoint_state_mode",
        "legacy_server_owned",
        "Endpoint-owned MLS state is already admitted but its sealed local snapshot is missing",
        "state.join_from_welcome(",
        "module.EndpointMlsState.restore(",
        "endpointApplyBootstrapCommits(restored,bootstrap,index)",
    ] {
        assert!(
            client.contains(invariant),
            "missing reference client invariant {invariant}"
        );
    }
    for invariant in [
        "register_endpoint_mls_key_package",
        "mls_admission_context",
        "with_mls_admission_store",
        "RealtimeMlsEndpointStateMode::Register",
        "RealtimeMlsEndpointStateMode::Restore",
        "RealtimeMlsEndpointStateMode::LegacyServerOwned",
    ] {
        assert!(
            realtime.contains(invariant),
            "missing realtime MLS invariant {invariant}"
        );
    }
    assert!(
        !universal.contains("create_mls_device_key_package(&owner.scope, &participant.device_id)"),
        "Universal Conference must not create participant MLS KeyPackages server-side"
    );
}

#[test]
fn browser_compatibility_matrix_runs_real_desktop_and_simulator_backed_mobile_browsers() {
    let workflow = read(".github/workflows/browser-compatibility.yml");
    let probe = read("tools/browser_compatibility_probe.py");
    let mobile_probe = read("tools/mobile_browser_compatibility_probe.py");
    let ios_safari_runner = read("tools/ios_safari_probe_runner.py");
    let android_first_run = read("tools/android_chrome_first_run.py");
    let android_probe_runner = read("tools/android_chrome_probe_runner.py");
    let mobile_probe_js = read("crates/ucr-realtime-web/static/mobile-browser-probe.js");
    let client = read("crates/ucr-realtime-web/static/client.html");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let universal = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let spec = read("spec/browser-compatibility.md");

    assert_browser_workflow(&workflow);
    assert_desktop_probe(&probe);
    assert_mobile_probe(&mobile_probe, &mobile_probe_js);
    for invariant in [
        "xcrun",
        "simctl",
        "openurl",
        "timeout=openurl_timeout",
        "mobile_browser_compatibility_probe.py",
        "com.apple.mobilesafari",
        "bootstatus",
        "shutdown",
        "erase",
        "com.apple.CoreSimulator.CoreSimulatorService",
        "restart_coresimulator_control_plane",
        "CoreSimulator discovery failed; recycling control plane",
        "simctl list timed out after 120s",
        "timeout=120",
        "timeout=300",
        "could not enumerate available iPhone simulators after recovery",
        "best_effort",
        "max-simulators",
    ] {
        assert!(
            ios_safari_runner.contains(invariant),
            "missing iOS Safari recovery invariant {invariant}"
        );
    }
    for invariant in [
        "FirstRunActivity",
        "uiautomator",
        "Use without an account",
        "Accept & continue",
        "com.android.chrome",
    ] {
        assert!(
            android_first_run.contains(invariant),
            "missing Android Chrome first-run invariant {invariant}"
        );
    }
    for invariant in [
        "mobile_browser_compatibility_probe.py",
        "android_chrome_first_run.py",
        "adb",
        "reverse",
        "navigation_attempts",
        "evidence_wait_seconds",
        "Android Chrome produced no mobile browser evidence",
        "navigation recovery.",
        "FirstRunActivity",
        "ChromeTabbedActivity",
    ] {
        assert!(
            android_probe_runner.contains(invariant),
            "missing Android Chrome recovery invariant {invariant}"
        );
    }
    assert!(
        !workflow.contains("skip_first_run_experience"),
        "mobile evidence must not rely on the removed Chrome FRE shortcut"
    );
    assert_endpoint_mls_binding(&client, &realtime, &universal);

    assert!(spec.contains("Android Chrome"));
    assert!(spec.contains("iOS Safari"));
    assert!(spec.contains("simulator/emulator-backed mobile browsers"));
    assert!(spec.contains("**not** accepted as production evidence"));
    assert!(spec.contains("does not by itself prove TURN reachability"));
}

#[test]
fn ci_runner_bootstrap_prefers_preinstalled_tools_and_bounds_apt_network_calls() {
    let workflows = [
        read(".github/workflows/ci.yml"),
        read(".github/workflows/conformance.yml"),
        read(".github/workflows/phase44-supply-chain.yml"),
        read(".github/workflows/phase45-production-hardening.yml"),
        read(".github/workflows/production-release-linux.yml"),
    ];
    let combined = workflows.join("\n");
    let apt_installer = read("tools/ci_install_apt_packages.sh");

    for invariant in [
        "command -v cmake",
        "command -v cc",
        "command -v c++",
        "command -v make",
        "command -v protoc",
        "bash tools/ci_install_apt_packages.sh cmake build-essential",
        "bash tools/ci_install_apt_packages.sh protobuf-compiler",
    ] {
        assert!(
            combined.contains(invariant),
            "missing CI bootstrap invariant {invariant}"
        );
    }

    assert!(
        !combined
            .contains("sudo apt-get update -qq && sudo apt-get install -y --no-install-recommends"),
        "CI workflows must not depend on an unbounded apt update/install chain"
    );

    for invariant in [
        "Acquire::Retries=3",
        "Acquire::http::Timeout=20",
        "Acquire::https::Timeout=20",
        "timeout 120s",
        "timeout 180s",
        "apt install attempt",
    ] {
        assert!(
            apt_installer.contains(invariant),
            "missing bounded apt installer invariant {invariant}"
        );
    }
}
