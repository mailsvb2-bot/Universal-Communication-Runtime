use std::{fs, path::Path};

#[test]
fn conference_white_label_remains_presentation_only() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let embed = fs::read_to_string(workspace.join("sdk/typescript/src/conference_embed.ts"))
        .expect("read conference embed helper");
    assert!(embed.contains("const BRANDING_FRAGMENT_KEY = \"ucr_brand\""));
    assert!(embed.contains("normalizeConferenceBranding"));
    assert!(embed.contains("withConferenceBranding"));

    let browser =
        fs::read_to_string(workspace.join("crates/ucr-realtime-web/static/client.html"))
            .expect("read conference browser client");
    assert!(browser.contains("const BRANDING_FRAGMENT_KEY=\"ucr_brand\""));
    assert!(browser.contains("function applyBrandingFromFragment(params)"));

    let public_contract =
        fs::read_to_string(workspace.join("proto/ucr/v1/universal_conference.proto"))
            .expect("read universal conference contract");
    assert!(
        !public_contract.contains("ucr_brand"),
        "presentation fragment must not become a public Conference field"
    );
    assert!(
        !public_contract.contains("ConferenceBranding"),
        "branding must not become canonical Conference state"
    );

    let canonical_owner =
        fs::read_to_string(workspace.join("crates/ucr-core/src/universal_conference.rs"))
            .expect("read canonical universal conference owner");
    assert!(
        !canonical_owner.contains("ConferenceBranding"),
        "canonical Conference owner must not depend on presentation branding"
    );
}
