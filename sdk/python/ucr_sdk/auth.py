"""Thin Service Principal metadata helper for generated ucr.v1 Python clients."""

from dataclasses import dataclass
from typing import Final

CREDENTIAL_ID_METADATA_KEY: Final = "ucr-service-credential-id-bin"
CREDENTIAL_SECRET_METADATA_KEY: Final = "ucr-service-credential-secret-bin"


@dataclass(frozen=True, repr=False)
class ServiceCredential:
    """Opaque credential bytes; canonical validation remains server-owned."""

    credential_id: bytes
    secret: bytes

    def metadata(self) -> tuple[tuple[str, bytes], tuple[str, bytes]]:
        """Return exact binary gRPC metadata without modifying protobuf bodies."""
        return (
            (CREDENTIAL_ID_METADATA_KEY, self.credential_id),
            (CREDENTIAL_SECRET_METADATA_KEY, self.secret),
        )

    def __repr__(self) -> str:
        return f"ServiceCredential(credential_id_len={len(self.credential_id)}, secret=[REDACTED])"
