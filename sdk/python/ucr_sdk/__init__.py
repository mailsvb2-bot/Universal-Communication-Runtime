"""Prepared Python helpers for the generated ucr.v1 public client."""

from .auth import (
    CREDENTIAL_ID_METADATA_KEY,
    CREDENTIAL_SECRET_METADATA_KEY,
    ServiceCredential,
)
from .conference import UniversalConferenceClient, UniversalConferenceHttpError

__all__ = [
    "CREDENTIAL_ID_METADATA_KEY",
    "CREDENTIAL_SECRET_METADATA_KEY",
    "ServiceCredential",
    "UniversalConferenceClient",
    "UniversalConferenceHttpError",
]
