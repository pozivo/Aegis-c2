# Alpha API

The API exists to validate the domain model. It is not stable yet.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| POST | `/v1/engagements` | Create scoped engagement |
| POST | `/v1/agents/enroll` | Enroll lab agent |
| POST | `/v1/agents/{id}/heartbeat` | Update presence |
| GET | `/v1/audit` | Inspect alpha audit events |

All mutating endpoints will later require authenticated identities,
idempotency keys, explicit organization context, and policy decisions.
