# Threat model

## Assets

- Operator identities and sessions
- Agent and gateway private keys
- Engagement scopes and approvals
- Task payloads and results
- Audit history
- Signing and update infrastructure

## Primary threats and controls

| Threat | Initial control | Production control |
|---|---|---|
| Stolen operator session | Short sessions | OIDC, WebAuthn, device binding |
| Rogue operator | Roles and audit events | ABAC, dual approval, scoped grants |
| Compromised gateway | Separation from database | mTLS, least privilege, rotation |
| Replayed task | Task IDs and deadlines | Signed nonce and replay cache |
| Out-of-scope operation | Engagement required | CIDR/DNS policy at API and agent |
| Malicious plugin | No alpha plugins | WASM sandbox, capability manifest |
| Audit tampering | SHA-256 hash chain | Persistent journal and external anchoring |
| Supply-chain compromise | Minimal images | SBOM, provenance, signed releases |
| Agent impersonation | Enrollment association | One-time enrollment plus mTLS cert |
| Resource exhaustion | Body/time limits | Quotas, backpressure, rate limits |

## Explicit alpha limitations

- A single shared operator bearer token protects engagement creation and audit
  reads. It has no per-user identity, roles, rotation, or session lifecycle;
  bind to loopback only.
- API state is persisted to PostgreSQL. The initial schema has no versioned
  upgrade mechanism and the database owner can still alter its contents.
- One-time enrollment and per-agent heartbeat tokens are implemented, but
  agent mTLS, rotation, and revocation are not.
- Audit events are hash chained but not externally anchored.
- CIDR strings are parsed at creation but scope is not enforced on agent traffic.
- The alpha agent keeps its heartbeat token only in memory, so restarting it
  requires a new engagement and enrollment.

The alpha must not be deployed outside a disposable local lab.
