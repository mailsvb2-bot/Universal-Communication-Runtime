#!/usr/bin/env python3
"""Executable Phase-41 Python SDK host probe."""

from ucr_sdk.auth import (
    CREDENTIAL_ID_METADATA_KEY,
    CREDENTIAL_SECRET_METADATA_KEY,
    ServiceCredential,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    credential_id = bytes((0x00, 0x01, 0xFE, 0xFF))
    secret = bytes((0xDE, 0xAD, 0xBE, 0xEF))
    credential = ServiceCredential(credential_id, secret)
    metadata = credential.metadata()

    require(len(metadata) == 2, "Python SDK emitted unexpected metadata entries")
    require(metadata[0] == (CREDENTIAL_ID_METADATA_KEY, credential_id), "credential id drifted")
    require(metadata[1] == (CREDENTIAL_SECRET_METADATA_KEY, secret), "credential secret drifted")

    rendered = repr(credential)
    require("[REDACTED]" in rendered, "Python credential diagnostics lost redaction")
    require("deadbeef" not in rendered.lower(), "Python diagnostics exposed secret bytes")

    # bytes are immutable and therefore cannot be changed through returned metadata.
    require(metadata[0][1] is credential_id, "Python helper unexpectedly rewrote opaque id bytes")
    require(metadata[1][1] is secret, "Python helper unexpectedly rewrote opaque secret bytes")
    print("UCR_PHASE41_PYTHON_OK")


if __name__ == "__main__":
    main()
