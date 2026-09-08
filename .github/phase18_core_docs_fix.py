from pathlib import Path

path = Path("crates/ucr-core/src/authorized_runtime.rs")
text = path.read_text()

docs = {
    "    pub fn persist_message(\n":
        "    ///\n    /// # Errors\n    /// Returns authorization failure before persistence, rejects the generic path for Group messages, and propagates durable-store failures.\n",
    "    pub fn message(\n":
        "    ///\n    /// # Errors\n    /// Returns authorization or durable-store failures; Group messages are deliberately hidden from this generic path.\n",
    "    pub fn create_group(\n":
        "    /// Creates one canonical Group through the authorization-enforcing durable owner.\n    ///\n    /// # Errors\n    /// Returns authorization failure before storage, or an explicit invalid/conflict/storage failure from atomic Group creation.\n",
    "    pub fn group(\n":
        "    /// Reads one Group subject to authorization and private-membership visibility.\n    ///\n    /// # Errors\n    /// Returns authorization or durable-store failures. Private non-members receive no Group existence disclosure.\n",
    "    pub fn group_membership(\n":
        "    /// Reads one membership only for an authorized active Group member.\n    ///\n    /// # Errors\n    /// Returns authorization or durable-store failures; inactive callers cannot use membership lookup as an existence oracle.\n",
    "    pub fn group_memberships(\n":
        "    /// Reads one bounded canonical membership set for an authorized active Group member.\n    ///\n    /// # Errors\n    /// Returns authorization, membership, invalid-bound, or durable-store failures.\n",
    "    pub fn apply_group_change(\n":
        "    /// Applies one authenticated Group mutation through the atomic canonical Group owner.\n    ///\n    /// # Errors\n    /// Returns authorization, role/membership, stale-revision, conflict, validation, or durable-store failures.\n",
    "    pub fn persist_group_message(\n":
        "    /// Persists one Group Message through the membership-gated canonical Message owner.\n    ///\n    /// # Errors\n    /// Returns authorization, inactive-membership, validation, conflict, or durable-store failures.\n",
    "    pub fn group_message(\n":
        "    /// Reads one Group Message through the membership/history-gated canonical Message owner.\n    ///\n    /// # Errors\n    /// Returns authorization, inactive-membership, history-policy, or durable-store failures.\n",
}

for marker, doc in docs.items():
    pos = text.find(marker)
    if pos < 0:
        raise SystemExit(f"authorized runtime marker missing: {marker.strip()}")
    prefix = text[max(0, pos - 500):pos]
    if "# Errors" not in prefix:
        text = text[:pos] + doc + text[pos:]

path.write_text(text)
