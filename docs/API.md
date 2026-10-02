# Alpha API

The API exists to validate the domain model. It is not stable yet.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness |
| POST | `/v1/engagements` | Create scoped engagement |
| POST | `/v1/agents/enroll` | Enroll lab agent |
| POST | `/v1/agents/{id}/heartbeat` | Update presence |
| GET | `/v1/audit` | Inspect alpha audit events |

All mutating endpoints will later require authenticated identities,
idempotency keys, explicit organization context, and policy decisions.

Request bodies are limited to 32 KiB, reject unknown JSON fields, and apply
basic inventory field limits. Engagement scope values must be valid CIDRs.

Creating an engagement returns an `enrollment_token` once. Enrollment requires
it as `Authorization: Bearer <token>`. The control plane stores only its SHA-256
digest, compares it in constant time, and consumes it after successful use.
