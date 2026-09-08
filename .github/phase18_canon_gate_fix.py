import re
from pathlib import Path

canon = Path("crates/ucr-architecture-tests/tests/canon_gates.rs")
text = canon.read_text()

helper = '''fn current_sqlite_schema_version(source: &str) -> u32 {
    const PREFIX: &str = "pub const SQLITE_SCHEMA_VERSION: u32 = ";
    source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(PREFIX)
                .and_then(|value| value.strip_suffix(';'))
                .and_then(|value| value.parse::<u32>().ok())
        })
        .expect("current SQLite schema version declaration")
}

'''
if "fn current_sqlite_schema_version(" not in text:
    marker = "use std::{fs, path::Path};\n\n"
    if marker not in text:
        raise SystemExit("canon imports marker missing")
    text = text.replace(marker, marker + helper, 1)

pattern = re.compile(
    r'assert!\((sqlite(?:_root)?)\.contains\("pub const SQLITE_SCHEMA_VERSION: u32 = 20;?"\)\);'
)
text, version_replacements = pattern.subn(
    lambda match: f"assert!(current_sqlite_schema_version(&{match.group(1)}) >= 20);",
    text,
)
if version_replacements < 15 and "current_sqlite_schema_version(&sqlite" not in text:
    raise SystemExit(f"expected historical schema assertions or prior repair, replaced {version_replacements}")

method_marker = '    "message",\n'
method_block = method_marker + '''    "create_group",
    "group",
    "group_membership",
    "group_memberships",
    "apply_group_change",
    "persist_group_message",
    "group_message",
'''
if '    "create_group",\n' not in text:
    if method_marker not in text:
        raise SystemExit("authorized methods marker missing")
    text = text.replace(method_marker, method_block, 1)

permission_marker = '    "MESSAGE_WRITE_PERMISSION",\n'
permission_block = permission_marker + '''    "GROUP_CREATE_PERMISSION",
    "GROUP_READ_PERMISSION",
    "GROUP_MANAGE_PERMISSION",
'''
if '    "GROUP_CREATE_PERMISSION",\n' not in text:
    if permission_marker not in text:
        raise SystemExit("authorized permissions marker missing")
    text = text.replace(permission_marker, permission_block, 1)

old_loop = '''    for method in AUTHORIZED_DURABLE_METHODS {
        assert!(
            runtime.contains(&format!("pub fn {method}(")),
            "authorized runtime method missing: {method}"
        );
    }
    assert_eq!(
        runtime.matches("pub fn ").count(),
        AUTHORIZED_DURABLE_METHODS.len()
    );
    assert_eq!(
        runtime.matches("self.require(").count(),
        AUTHORIZED_DURABLE_METHODS.len()
    );
'''
new_loop = '''    for method in AUTHORIZED_DURABLE_METHODS {
        let marker = format!("pub fn {method}(");
        let start = runtime
            .find(&marker)
            .unwrap_or_else(|| panic!("authorized runtime method missing: {method}"));
        let tail = &runtime[start + marker.len()..];
        let end = tail.find("\\n    pub fn ").unwrap_or(tail.len());
        assert!(
            tail[..end].contains("self.require("),
            "authorized runtime method lacks an explicit permission check: {method}"
        );
    }
    let public_methods = runtime
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("pub fn ")
                .and_then(|rest| rest.split_once('(').map(|(name, _)| name))
        })
        .collect::<Vec<_>>();
    assert_eq!(public_methods.len(), AUTHORIZED_DURABLE_METHODS.len());
    for method in public_methods {
        assert!(
            AUTHORIZED_DURABLE_METHODS.contains(&method),
            "untracked authorized runtime method: {method}"
        );
    }
'''
if old_loop in text:
    text = text.replace(old_loop, new_loop, 1)
elif "authorized runtime method lacks an explicit permission check" not in text:
    raise SystemExit("authorized runtime count gate marker missing")

text = text.replace(
    'assert!(adr.contains("mirrors all 32 methods"));',
    'assert!(adr.contains("every currently implemented tenant-scoped durable capability"));',
    1,
)
text = text.replace(
    'assert!(permission_spec.contains("54 externally callable tenant-scoped durable methods"));',
    'assert!(permission_spec.contains("Phase 18 contributes seven Group façade methods"));',
    1,
)
canon.write_text(text)

adr = Path("docs/adr/0028-tenant-scoped-durable-runtime-operations-require-explicit-permissions.md")
text = adr.read_text()
old = "`AuthorizedDurableRuntime` is the authorization-enforcing runtime façade for every currently implemented tenant-scoped durable capability. It mirrors all 32 methods owned by `PermissionGrantStore`, `TrustedSigningKeyStore`, `RecoveryPlanStore`, `CommandAcceptanceStore`, `ConversationStore`, `MessageStore`, `DeliveryStore`, `SyncStore`, `EventJournalStore`, `AntiEntropyStore`, and `CommandOutcomeStore`."
new = "`AuthorizedDurableRuntime` is the authorization-enforcing runtime façade for every currently implemented tenant-scoped durable capability. Architecture tests enumerate the complete façade method set and require it to stay aligned as canonical owners grow. The covered durable owners include permission/service administration, Identity/Device, trusted keys, recovery, Commands, Conversation, Message, Communication Intent, Delivery, Sync, Event/Anti-Entropy, and Phase 18 `GroupStore` / `GroupMessageStore`; Group authorization reuses this same boundary rather than creating a second policy brain."
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit("ADR 0028 authorization surface marker missing")
adr.write_text(text)

spec = Path("spec/permissions.md")
text = spec.read_text()
text = text.replace(
    "conversations, messages, Communication Intents, delivery, sync, events, Service Principal administration, and Anti-Entropy.",
    "conversations, messages, Groups, Communication Intents, delivery, sync, events, Service Principal administration, and Anti-Entropy.",
    1,
)
text = text.replace(
    "conversation read/write; message read/write; Communication Intent read/write",
    "conversation read/write; message read/write; Group create/read/manage (`ucr.group.*`); Communication Intent read/write",
    1,
)
old_count = "the current façade covers 54 externally callable tenant-scoped durable methods and the registry contains 43 unique permission IDs."
old_phase_count = "the current façade covers 61 externally callable tenant-scoped durable methods and the registry contains 46 unique permission IDs. Phase 18 contributes seven Group façade methods and three protocol-owned Group permissions; later phases must extend these explicit enumerations rather than freeze a historical count."
new_count = "Phase 18 contributes seven Group façade methods and three protocol-owned Group permissions. Architecture tests enumerate the complete current façade and permission vocabulary directly, so later phases extend those explicit enumerations without freezing a historical method or permission count in prose."
if old_count in text:
    text = text.replace(old_count, new_count, 1)
elif old_phase_count in text:
    text = text.replace(old_phase_count, new_count, 1)
elif new_count not in text:
    raise SystemExit("permissions authorization-surface marker missing")
spec.write_text(text)
