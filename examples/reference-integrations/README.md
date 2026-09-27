# UCR reference integrations

These examples prove that the Universal Conference API can be consumed without ClientPlatform-specific models or internal UCR identifiers.

All examples use the same public `/v1` REST adapter and the same integration-owned references:

1. create a conference with `external_conference_id`;
2. ensure owner and attendee by `external_user_id`;
3. ensure their canonical devices without learning Device IDs;
4. prepare the canonical conference runtime;
5. move the conference through waiting to live;
6. issue the attendee a short-lived join grant.

## Environment

- `UCR_BASE_URL` — trusted HTTPS edge in front of `ucr-conference-web`, for example `https://ucr.example.test`.
- `UCR_ACCESS_TOKEN` — short-lived machine Bearer for the exact integration.
- `UCR_TENANT_ID` — tenant.
- `UCR_INTEGRATION_ID` — Service Account/integration ID represented by the token.

Never put `UCR_ACCESS_TOKEN` into browser or mobile-web source. Browser examples consume only a personal join URL returned by a trusted backend.

## Runnable proofs

```bash
python3 examples/reference-integrations/python_backend.py --self-test
node examples/reference-integrations/node_backend.mjs --self-test
```

Without `--self-test`, both backend examples execute the real public API flow using the environment above and print only the resulting conference ID and join URL.

`simple-html/index.html` and `mobile-web/index.html` demonstrate two consumers of the issued join URL. They do not contain machine credentials or reimplement Conference business logic.
