# Phase 17 Chat test matrix

| Invariant | Executable evidence |
| --- | --- |
| Direct chat persists through canonical owner | `direct_chat_send_and_bounded_transcript_reuse_canonical_message_store` |
| Transcript is bounded/deduplicated/deterministic | same reference test plus `MAX_TRANSCRIPT_BATCH_ITEMS` gate |
| Group is not smuggled into Phase 17 | `phase17_rejects_group_conversation_instead_of_implementing_phase18_implicitly` |
| Read cannot skip Delivered | `read_requires_delivered_state_and_records_read_by_user_through_delivery_owner` |
| Read uses explicit user evidence | same test plus architecture gate for `ReadByUser` |
| Typing is ephemeral and TTL bounded | `typing_is_ttl_bounded_and_only_published_to_ephemeral_sink`, `typing_above_ttl_ceiling_is_rejected` |
| Service Account typing fails closed without admission gate | `service_account_typing_fails_closed_without_ephemeral_admission_gate` |
| Tenant scope is exact even with permissive authorizer | `subject_cannot_cross_tenant_even_with_permissive_authorizer` |
| No second Message/Conversation/Delivery/Route owner | `phase17_chat_creates_no_second_message_conversation_delivery_or_route_brain` |
