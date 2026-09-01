use std::{fs, path::Path};

const FORBIDDEN_CORE_TERMS: &[&str] = &[
    "telegram",
    "vk_message",
    "max_message",
    "clientplatform",
    "businessaios",
    "send_via_telegram",
    "send_via_vk",
    "send_via_max",
];

fn collect_files(path: &Path, output: &mut Vec<std::path::PathBuf>) {
    let entries = fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "failed to read architecture-test path {}: {error}",
            path.display()
        )
    });
    for entry in entries {
        let entry = entry.expect("valid directory entry");
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_files(&entry_path, output);
        } else if matches!(
            entry_path.extension().and_then(|value| value.to_str()),
            Some("rs" | "proto")
        ) {
            output.push(entry_path);
        }
    }
}

#[test]
fn canonical_core_and_protocol_do_not_contain_product_specific_brains() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let mut files = Vec::new();
    for relative in [
        "crates/ucr-model/src",
        "crates/ucr-protocol/src",
        "crates/ucr-core/src",
        "proto",
    ] {
        collect_files(&workspace.join(relative), &mut files);
    }

    assert!(!files.is_empty(), "architecture gate scanned no files");
    for file in files {
        let content = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        let lower = content.to_ascii_lowercase();
        for forbidden in FORBIDDEN_CORE_TERMS {
            assert!(
                !lower.contains(forbidden),
                "forbidden product/provider coupling `{forbidden}` found in {}",
                file.display()
            );
        }
    }
}

#[test]
fn protobuf_contract_is_versioned_and_language_independent() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto_root = workspace.join("proto/ucr/v1");
    let mut files = Vec::new();
    collect_files(&proto_root, &mut files);
    assert!(!files.is_empty(), "no protobuf contract files found");

    for file in files {
        let content = fs::read_to_string(&file).expect("read protobuf file");
        assert!(
            content.contains("package ucr.v1;"),
            "{} does not declare the versioned public package",
            file.display()
        );
    }
}
