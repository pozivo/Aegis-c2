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

- No authentication: bind to loopback only.
- In-memory state disappears on restart.
- Enrollment token and mTLS are not implemented.
- Audit events are not yet hash chained.
- CIDR strings are recorded but not yet parsed and enforced.

The alpha must not be deployed outside a disposable local lab.
