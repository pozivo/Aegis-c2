# Alpha API

The API exists to validate the domain model. It is not stable yet.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness |
| POST | `/v1/engagements` | Create scoped engagement; operator token required |
| POST | `/v1/agents/enroll` | Enroll lab agent |
| POST | `/v1/agents/{id}/heartbeat` | Update presence; agent heartbeat token required |
| GET | `/v1/audit` | Inspect alpha audit events; operator token required |

Set `AEGIS_OPERATOR_TOKEN` to at least 32 characters before starting the API.
Pass `Authorization: Bearer <operator token>` to create engagements or read
audit history. This shared lab secret is not a replacement for OIDC, roles,
idempotency keys, organization context, and policy decisions.

Request bodies are limited to 32 KiB, reject unknown JSON fields, and apply
basic inventory field limits. Engagement scope values must be valid CIDRs.

Creating an engagement returns an `enrollment_token` once. Enrollment requires
it as `Authorization: Bearer <token>`. The control plane stores only its SHA-256
digest, compares it in constant time, and consumes it after successful use.
Enrollment returns a separate `heartbeat_token` once. Send it as
`Authorization: Bearer <heartbeat token>` to the heartbeat endpoint. The
server stores its SHA-256 digest. The alpha agent keeps it in memory only.

Audit events include `prev_hash` and `hash`. The readiness endpoint recomputes
the persistent chain and returns HTTP 503 when audit integrity is invalid.
