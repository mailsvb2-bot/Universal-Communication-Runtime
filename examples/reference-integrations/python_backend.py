#!/usr/bin/env python3
import argparse
import base64
import json
import os
import time
import urllib.parse
import urllib.request


def b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def config():
    required = ["UCR_BASE_URL", "UCR_ACCESS_TOKEN", "UCR_TENANT_ID", "UCR_INTEGRATION_ID"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise SystemExit("missing environment: " + ", ".join(missing))
    return {name: os.environ[name] for name in required}


def post(cfg, path, body):
    request = urllib.request.Request(
        cfg["UCR_BASE_URL"].rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "authorization": "Bearer " + cfg["UCR_ACCESS_TOKEN"],
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def flow_payloads(cfg, now_ms=None):
    now_ms = now_ms or int(time.time() * 1000)
    scope = {"tenant_id": cfg["UCR_TENANT_ID"]}
    integration_id = cfg["UCR_INTEGRATION_ID"]
    external_conference = b64("reference-webinar-001")
    create = {
        "scope": scope,
        "integration_id": integration_id,
        "external_conference_id_b64": external_conference,
        "idempotency_key": "reference-create-001",
        "mode": "webinar",
        "schedule": {
            "starts_at_unix_ms": now_ms + 300_000,
            "planned_end_unix_ms": now_ms + 3_900_000,
            "join_before_seconds": 900,
            "join_after_seconds": 300,
            "timezone": "UTC",
        },
    }
    return scope, integration_id, create


def run():
    cfg = config()
    scope, integration_id, create = flow_payloads(cfg)
    conference = post(cfg, "/v1/conferences", create)["conference"]
    conference_id = conference["conference_id"]

    def participant(external_user, role, key):
        return post(cfg, "/v1/participants", {
            "scope": scope, "conference_id": conference_id, "integration_id": integration_id,
            "external_user_id_b64": b64(external_user), "role": role, "idempotency_key": key,
        })

    participant("owner-001", "owner", "reference-owner-001")
    participant("attendee-001", "attendee", "reference-attendee-001")
    for external_user, key in [("owner-001", "reference-owner-device-001"), ("attendee-001", "reference-attendee-device-001")]:
        post(cfg, "/v1/participant-devices", {
            "scope": scope, "conference_id": conference_id, "integration_id": integration_id,
            "external_user_id_b64": b64(external_user), "idempotency_key": key,
        })

    post(cfg, "/v1/conferences/runtime", {
        "scope": scope, "conference_id": conference_id, "integration_id": integration_id,
        "idempotency_key": "reference-runtime-001",
    })
    for target in ("waiting", "live"):
        post(cfg, "/v1/conferences/lifecycle", {
            "scope": scope, "conference_id": conference_id, "integration_id": integration_id,
            "target": target, "idempotency_key": "reference-lifecycle-" + target,
        })
    grant = post(cfg, "/v1/join-grants", {
        "scope": scope, "conference_id": conference_id, "integration_id": integration_id,
        "external_user_id_b64": b64("attendee-001"), "ttl_seconds": 900,
        "use_policy": "single_use", "idempotency_key": "reference-join-001",
    })["grant"]
    print(json.dumps({"conference_id": conference_id, "join_url": grant["join_url"]}))


def self_test():
    cfg = {"UCR_TENANT_ID": "tenant", "UCR_INTEGRATION_ID": "integration"}
    scope, integration_id, create = flow_payloads(cfg, 1_700_000_000_000)
    assert scope == {"tenant_id": "tenant"}
    assert integration_id == "integration"
    assert create["mode"] == "webinar"
    assert create["external_conference_id_b64"] == b64("reference-webinar-001")
    assert create["idempotency_key"] == "reference-create-001"
    assert create["schedule"]["join_before_seconds"] == 900
    print("reference Python integration self-test: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test() if args.self_test else run()
