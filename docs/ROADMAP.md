# Roadmap

## M0 — Scaffold

- [x] Project structure
- [x] Engagement creation
- [x] Agent enrollment and heartbeat
- [x] Basic audit events
- [x] Rootless, read-only container profile
- [ ] Automated tests and CI

## M1 — Secure control plane

- [ ] PostgreSQL migrations
- [ ] OIDC and WebAuthn
- [ ] Organization-scoped RBAC
- [ ] CIDR and hostname scope validation
- [ ] Expiring one-time enrollment tokens
- [ ] Agent mTLS certificates and rotation
- [ ] Hash-chained audit journal

## M2 — Reliable orchestration

- [ ] NATS JetStream
- [ ] Signed task envelopes
- [ ] Idempotency and replay protection
- [ ] Cancellation, deadlines, and backpressure
- [ ] Inventory task schema
- [ ] CLI and operator dashboard

## M3 — Differentiators

- [ ] Policy-as-code
- [ ] Two-person approval workflows
- [ ] WASM plugin SDK and capability manifests
- [ ] OpenTelemetry traces and metrics
- [ ] Engagement timeline replay
- [ ] MITRE ATT&CK tagging and purple-team exports
- [ ] Reproducible builds, SBOM, and Sigstore releases

## Release gates

No remote-execution task type is accepted until authentication, mTLS, strict
scope enforcement, signed tasks, audit integrity, and revocation are complete.
