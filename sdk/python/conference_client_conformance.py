#!/usr/bin/env python3
"""Executable high-level Python Universal Conference client conformance probe."""

from ucr_sdk.conference import UniversalConferenceClient, UniversalConferenceHttpError


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


calls = []


def fake_transport(path, token, body):
    calls.append((path, token, body))
    if path == "/v1/conferences":
        return {"conference": {"conference_id": "conference-1"}}
    if path == "/v1/participants":
        return {
            "participant": {
                "external_user_id_b64": "dXNlci0x",
                "role": "attendee",
                "audio_muted": False,
                "camera_allowed": True,
                "publish_audio_allowed": True,
                "publish_video_allowed": True,
                "active": True,
                "screen_share_allowed": False,
            }
        }
    if path == "/v1/participant-devices":
        return {"device": {"external_user_id_b64": "dXNlci0x", "active": True}}
    if path == "/v1/join-grants":
        return {
            "grant": {
                "session_id": "session-1",
                "join_url": "https://join.example/#ucr_join=opaque",
                "expires_at_unix_ms": 1_700_000_900_000,
            }
        }
    if path == "/v1/attendance":
        raise UniversalConferenceHttpError(
            status=429,
            message="slow down",
            code="RATE_LIMITED",
            retryable=True,
            retry_after_ms=2500,
        )
    return {"acknowledgement": {"accepted": True}}


client = UniversalConferenceClient(
    "https://ucr.example",
    "machine-token",
    transport=fake_transport,
)
conference = client.create_conference(
    scope={"tenant_id": "tenant"},
    integration_id="integration",
    external_conference_id="event-1",
    idempotency_key="conference-1",
    mode="webinar",
    schedule={"starts_at_unix_ms": 1_700_000_000_000},
)
require(conference["conference_id"] == "conference-1", "conference response drifted")

context = {
    "scope": {"tenant_id": "tenant"},
    "integration_id": "integration",
    "conference_id": "conference-1",
}
participant = client.ensure_participant(context, "user-1", "attendee", "participant-1")
require(participant["role"] == "attendee", "participant response drifted")
device = client.ensure_participant_device(context, "user-1", "device-1")
require(device["active"] is True, "participant device readiness was discarded")
grant = client.issue_join_grant(
    context,
    "user-1",
    900,
    "single_use",
    "join-1",
)
require("#ucr_join=" in grant["join_url"], "join URL boundary drifted")

require(len(calls) == 4, "client performed hidden retries")
require(all(call[1] == "machine-token" for call in calls), "Bearer token transport drifted")
require(
    calls[0][2]["external_conference_id_b64"] == "ZXZlbnQtMQ==",
    "external conference ID encoding drifted",
)
require(
    calls[1][2]["external_user_id_b64"] == "dXNlci0x",
    "external user ID encoding drifted",
)

try:
    client.get_attendance(context, "user-1")
    raise SystemExit("canonical error was swallowed")
except UniversalConferenceHttpError as error:
    require(error.status == 429, "canonical HTTP status drifted")
    require(error.code == "RATE_LIMITED", "canonical error code drifted")
    require(error.retryable is True, "canonical retryability was discarded")
    require(error.retry_after_ms == 2500, "canonical retry delay was discarded")
    require("machine-token" not in str(error), "error diagnostics leaked machine token")

require(len(calls) == 5, "error path performed hidden retries")

try:
    UniversalConferenceClient._raise_for_error(302, {"redirect": "https://other.example"})
    raise SystemExit("redirect status was accepted as success")
except UniversalConferenceHttpError as redirect_error:
    require(redirect_error.status == 302, "redirect status was not preserved")

try:
    UniversalConferenceClient("http://public.example", "token")
    raise SystemExit("plaintext public base URL was accepted")
except ValueError:
    pass

try:
    client.update_participant(
        context,
        "user-1",
        "update-1",
        unsupported_permission=True,
    )
    raise SystemExit("unknown participant mutation field was accepted")
except ValueError:
    pass

print("UCR_PYTHON_CONFERENCE_CLIENT_OK")
