from pathlib import Path

path = Path("crates/ucr-core/src/authorized_runtime.rs")
text = path.read_text()

guard = '''        if subject.principal.kind == PrincipalKind::ServiceAccount
            && message.origin.principal_id.as_ref() != Some(&subject.principal.principal_id)
        {
            return Err(AuthorizedMutationError::Authorization(
                ucr_protocol::CanonicalError::new(
                    ucr_protocol::CanonicalErrorCode::PermissionDenied,
                ),
            ));
        }
'''

def insert_guard_after_require(text: str, method: str) -> str:
    start = text.find(method)
    if start < 0:
        raise SystemExit(f"method marker missing: {method.strip()}")
    end = text.find("\n    }\n", start)
    if end < 0:
        raise SystemExit(f"method end missing: {method.strip()}")
    segment = text[start:end]
    if guard.strip() in segment:
        return text
    marker = "        self.require(subject, &message.scope, MESSAGE_WRITE_PERMISSION)?;\n"
    pos = text.find(marker, start, end)
    if pos < 0:
        raise SystemExit(f"permission marker missing: {method.strip()}")
    pos += len(marker)
    return text[:pos] + guard + text[pos:]

text = insert_guard_after_require(text, "    pub fn persist_message(\n")
text = insert_guard_after_require(text, "    pub fn persist_group_message(\n")
path.write_text(text)
