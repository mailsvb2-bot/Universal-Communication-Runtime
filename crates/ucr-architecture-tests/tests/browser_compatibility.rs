use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn browser_compatibility_matrix_runs_real_desktop_browsers_and_keeps_mobile_truthful() {
    let workflow = read(".github/workflows/browser-compatibility.yml");
    let probe = read("tools/browser_compatibility_probe.py");
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
    assert!(workflow.contains("upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"));

    for invariant in [
        "real-desktop-browser-webdriver-smoke",
        "rtcPeerConnection",
        "restartIceFunction",
        "applyMediaPolicyFunction",
        "getUserMedia",
        "getDisplayMedia",
        "cryptoSubtle",
        "secureContext",
    ] {
        assert!(probe.contains(invariant), "missing browser probe invariant {invariant}");
    }

    assert!(spec.contains("Android Chrome"));
    assert!(spec.contains("iOS Safari"));
    assert!(spec.contains("pending real mobile browser run"));
    assert!(spec.contains("not accepted as production evidence"));
    assert!(spec.contains("does not by itself prove TURN reachability"));
}
