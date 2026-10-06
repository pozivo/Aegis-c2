# Aegis C2

Aegis C2 is a security-first orchestration platform for authorized red-team,
purple-team, training, and lab environments.

The project starts with a deliberately small capability set: agent enrollment,
heartbeat, host inventory, engagement scoping, and immutable-style audit events.
Arbitrary command execution is intentionally outside the alpha milestone.

## Alpha architecture

- `control-plane/`: Go HTTP API, transactional PostgreSQL store, and migrations
- `agent/`: Rust lab agent with an allowlisted inventory workflow
- `docs/`: architecture, threat model, roadmap, and API notes
- `deployments/`: local Docker Compose environment

## Security principles

1. Deny by default.
2. Every agent belongs to an active engagement.
3. Every engagement declares allowed CIDRs and an expiry.
4. Agent enrollment uses a one-time token; production will use mTLS identities.
5. Every state transition emits an audit event.
6. High-impact actions require explicit policy and multi-operator approval.
7. Plugins will run in isolated WASM sandboxes.

## Quick start

Prerequisites: Docker with Compose.

```bash
export AEGIS_DB_PASSWORD='choose-a-unique-local-lab-password'
export AEGIS_OPERATOR_TOKEN="$(openssl rand -hex 32)"
docker compose -f deployments/docker-compose.yml up --build
curl http://127.0.0.1:8080/healthz
```

PostgreSQL is private to the Compose network; its initial schema is installed
only when the named volume is new. The API uses PostgreSQL transactions for
engagements, one-time enrollment, heartbeat, and the audit chain. Existing
volumes need a separate migration before upgrading the schema. This alpha
uses a local operator bearer token but still lacks agent heartbeat identity
verification; use it only in a disposable local lab.

Create a lab engagement:

```bash
curl -X POST http://127.0.0.1:8080/v1/engagements \
  -H "Authorization: Bearer ${AEGIS_OPERATOR_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"name":"local-lab","allowed_cidrs":["127.0.0.0/8"],"expires_at":"2030-01-01T00:00:00Z"}'
```

The response contains a one-time `enrollment_token`. Start the lab agent with
`AEGIS_SERVER`, `AEGIS_ENGAGEMENT_ID`, and `AEGIS_ENROLLMENT_TOKEN`; the token
is stored only as a digest by the server and is consumed on successful use.

The alpha API has a single shared operator token and no authenticated agent heartbeat.
It is bound to loopback by Compose. Do not expose it to another network. OIDC,
mTLS, and policy enforcement are required before any non-local deployment.

## Development checks

```bash
cd control-plane && go test -race ./...
cd ../agent && cargo fmt --check && cargo check
```

GitHub Actions runs formatting, static analysis, tests, and builds for both
components on every pull request and push to `main`.

## Status

Milestone 0 scaffolding. See [ROADMAP.md](docs/ROADMAP.md).

## License

No license has been selected yet. Apache-2.0 is the proposed license, pending a
project-name and governance decision.
