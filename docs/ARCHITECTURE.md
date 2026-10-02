# Architecture

## Boundaries

The control plane owns identity, authorization, engagements, policy, task
state, and audit history. Gateways terminate agent transports but cannot read
operator credentials or directly mutate persistent state. Agents accept only
versioned, signed task schemas that are supported by their local allowlist.

## Target components

| Component | Responsibility | Trust level |
|---|---|---|
| Control API | State transitions and policy checks | High |
| Identity service | OIDC, WebAuthn, sessions | High |
| Policy engine | Scope, role, expiry, approvals | High |
| Gateway | Agent connectivity and rate limiting | Exposed |
| Event bus | Durable task and result delivery | Medium |
| Worker | Isolated plugin execution | Low |
| Audit service | Hash-chained event journal | High |
| Web/CLI | Operator clients | Untrusted input |
| Lab agent | Inventory and signed allowlisted tasks | Endpoint |

## Planned request path

1. Operator authenticates with OIDC and WebAuthn.
2. API validates role, engagement expiry, target scope, and action policy.
3. Sensitive actions enter a two-person approval state.
4. Control plane signs the approved task envelope.
5. Gateway delivers it to the assigned agent.
6. Agent verifies signature, schema version, deadline, nonce, and allowlist.
7. Results are signed, streamed, stored, and appended to the audit chain.

## Data model

- Organization
- Operator and Role
- Engagement and Scope
- Agent Identity
- Gateway
- Task, Approval, and Result
- Plugin Manifest
- Audit Event

The alpha uses memory storage to exercise API shapes. PostgreSQL and NATS are
the first infrastructure migration.
