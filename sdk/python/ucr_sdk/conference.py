"""High-level thin REST client for the canonical UCR Universal Conference API."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Sequence


def _b64_utf8(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _validated_base_url(value: str) -> str:
    trimmed = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(trimmed)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("UCR base URL must use HTTPS outside loopback development")
    if not parsed.netloc:
        raise ValueError("UCR base URL must be absolute")
    return trimmed


def _validated_token(value: str) -> str:
    token = value.strip()
    if not token or any(char.isspace() for char in token):
        raise ValueError("UCR access token must be a non-empty token")
    return token


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "redirect blocked for authenticated UCR request",
            headers,
            fp,
        )


@dataclass(frozen=True)
class UniversalConferenceHttpError(RuntimeError):
    status: int
    message: str
    code: str | None = None
    retryable: bool | None = None
    retry_after_ms: int | None = None

    def __str__(self) -> str:
        suffix = f" ({self.code})" if self.code else ""
        return f"HTTP {self.status}{suffix}: {self.message}"


Transport = Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]]


class UniversalConferenceClient:
    """Thin /v1 transport. Canonical business logic remains server-owned."""

    def __init__(
        self,
        base_url: str,
        access_token: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self._base_url = _validated_base_url(base_url)
        self._access_token = _validated_token(access_token)
        self._transport = transport or self._http_post

    def _http_post(self, path: str, token: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        request = urllib.request.Request(
            self._base_url + path,
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers={
                "authorization": "Bearer " + token,
                "content-type": "application/json",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=15) as response:
                payload = json.load(response)
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                payload = json.load(exc)
            except Exception:
                payload = {"error": {"message": "UCR request failed"}}
        self._raise_for_error(status, payload)
        return payload

    @staticmethod
    def _raise_for_error(status: int, payload: Mapping[str, Any]) -> None:
        error = payload.get("error")
        if 200 <= status < 300 and not isinstance(error, Mapping):
            return
        envelope = error if isinstance(error, Mapping) else {}
        raise UniversalConferenceHttpError(
            status=status,
            message=str(envelope.get("message") or "UCR request failed"),
            code=envelope.get("code") if isinstance(envelope.get("code"), str) else None,
            retryable=envelope.get("retryable") if isinstance(envelope.get("retryable"), bool) else None,
            retry_after_ms=envelope.get("retry_after_ms")
            if isinstance(envelope.get("retry_after_ms"), int)
            else None,
        )

    def _post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        # Exactly one transport call: explicit retries stay application-owned.
        return self._transport(path, self._access_token, body)

    def create_conference(
        self,
        *,
        scope: Mapping[str, Any],
        integration_id: str,
        external_conference_id: str,
        idempotency_key: str,
        mode: str,
        schedule: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._post("/v1/conferences", {
            "scope": dict(scope),
            "integration_id": integration_id,
            "external_conference_id_b64": _b64_utf8(external_conference_id),
            "idempotency_key": idempotency_key,
            "mode": mode,
            "schedule": dict(schedule),
        })
        return value["conference"]

    def resolve_conference(
        self,
        *,
        scope: Mapping[str, Any],
        integration_id: str,
        external_conference_id: str,
    ) -> Mapping[str, Any]:
        return self._post("/v1/conferences/resolve", {
            "scope": dict(scope),
            "integration_id": integration_id,
            "external_conference_id_b64": _b64_utf8(external_conference_id),
        })["conference"]

    def get_conference(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post("/v1/conferences/get", self._context_body(context))["conference"]

    def transition_conference(
        self, context: Mapping[str, Any], target: str, idempotency_key: str
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body.update({"target": target, "idempotency_key": idempotency_key})
        return self._post("/v1/conferences/lifecycle", body)["conference"]

    def set_entry_open(
        self, context: Mapping[str, Any], entry_open: bool, idempotency_key: str
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body.update({"entry_open": entry_open, "idempotency_key": idempotency_key})
        return self._post("/v1/conferences/entry", body)["conference"]

    def ensure_participant(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        role: str,
        idempotency_key: str,
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "role": role,
            "idempotency_key": idempotency_key,
        })
        return self._post("/v1/participants", body)["participant"]

    def ensure_participant_device(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        idempotency_key: str,
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "idempotency_key": idempotency_key,
        })
        return self._post("/v1/participant-devices", body)["device"]

    def update_participant(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        idempotency_key: str,
        **changes: Any,
    ) -> Mapping[str, Any]:
        allowed = {
            "role",
            "audio_muted",
            "camera_allowed",
            "publish_audio_allowed",
            "publish_video_allowed",
            "screen_share_allowed",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("unsupported participant changes: " + ", ".join(sorted(unknown)))
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "idempotency_key": idempotency_key,
            **changes,
        })
        return self._post("/v1/participants/update", body)["participant"]

    def remove_participant(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        idempotency_key: str,
    ) -> None:
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "idempotency_key": idempotency_key,
        })
        self._post("/v1/participants/remove", body)

    def list_participants(
        self, context: Mapping[str, Any], max_items: int = 100
    ) -> Sequence[Mapping[str, Any]]:
        body = self._context_body(context)
        body["max_items"] = max_items
        return self._post("/v1/participants/list", body)["participants"]

    def list_raised_hands(
        self, context: Mapping[str, Any], max_items: int = 100
    ) -> Sequence[str]:
        body = self._context_body(context)
        body["max_items"] = max_items
        return self._post("/v1/participants/raised-hands", body)["external_user_ids_b64"]

    def get_capabilities(
        self, scope: Mapping[str, Any], integration_id: str
    ) -> Mapping[str, Any]:
        return self._post("/v1/capabilities", {
            "scope": dict(scope),
            "integration_id": integration_id,
        })["capabilities"]

    def prepare_runtime(
        self, context: Mapping[str, Any], idempotency_key: str
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body["idempotency_key"] = idempotency_key
        return self._post("/v1/conferences/runtime", body)["runtime"]

    def issue_join_grant(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        ttl_seconds: int,
        use_policy: str,
        idempotency_key: str,
        *,
        not_before_unix_ms: int | None = None,
        not_after_unix_ms: int | None = None,
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "ttl_seconds": ttl_seconds,
            "use_policy": use_policy,
            "idempotency_key": idempotency_key,
        })
        if not_before_unix_ms is not None:
            body["not_before_unix_ms"] = not_before_unix_ms
        if not_after_unix_ms is not None:
            body["not_after_unix_ms"] = not_after_unix_ms
        return self._post("/v1/join-grants", body)["grant"]

    def revoke_join_grant(
        self, context: Mapping[str, Any], session_id: str, idempotency_key: str
    ) -> None:
        body = self._context_body(context)
        body.update({"session_id": session_id, "idempotency_key": idempotency_key})
        self._post("/v1/join-grants/revoke", body)

    def set_subscriptions(
        self,
        context: Mapping[str, Any],
        external_user_id: str,
        subscriptions: Sequence[Mapping[str, str]],
    ) -> None:
        body = self._context_body(context)
        body.update({
            "external_user_id_b64": _b64_utf8(external_user_id),
            "subscriptions": [
                {
                    "source_external_user_id_b64": _b64_utf8(item["source_external_user_id"]),
                    "media_kind": item["media_kind"],
                }
                for item in subscriptions
            ],
        })
        self._post("/v1/subscriptions", body)

    def get_attendance(
        self, context: Mapping[str, Any], external_user_id: str
    ) -> Mapping[str, Any]:
        body = self._context_body(context)
        body["external_user_id_b64"] = _b64_utf8(external_user_id)
        return self._post("/v1/attendance", body)["attendance"]

    @staticmethod
    def _context_body(context: Mapping[str, Any]) -> MutableMapping[str, Any]:
        return {
            "scope": dict(context["scope"]),
            "conference_id": context["conference_id"],
            "integration_id": context["integration_id"],
        }
