# Pulumi Backend

Pulumi CLI-compatible HTTP backend subset. All state lives in a single S3
bucket. Written in Go, shipped as a container image.

See [deployment hardening](docs/deployment.md) before exposing the service and
[release verification](docs/releases.md) before deploying an artifact.

## Architecture

- The CLI talks the Pulumi Cloud REST API to this service (`pulumi login https://...`).
- **State**: one S3 bucket, custom key layout `<org>/<project>/<stack>/…`
  (checkpoints, update records, history).
- **Locking**: S3 conditional writes (`If-None-Match: *`) with expiring leases;
  stale locks are breakable. Previews run lock-free.
- **Secrets**: always-on service-managed AES-256-GCM encryption. A distinct
  key is derived for each stack from the required, independent `secretsKey`.
- **Access**: static, default-deny OIDC group rules scope `read`, `write`,
  `delete`, and `secrets` operations to org/project/stack paths. The identity
  is the OIDC `(iss, sub)` pair; `preferred_username`, `name`, or `email` are
  display-only. The IdP must emit a top-level string-array `groups` claim.

## Configuration

Start from [`config.example.yaml`](config.example.yaml). Configure at least one
`signingKeys` entry and an independent base64-encoded 32-byte `secretsKey`.
`activeSigningKey` selects new tokens; leave old keys in the keyring until the
previous `tokenTTL` has elapsed. Authenticated mode requires an
`authorization` rule and denies unmatched requests.

`noAuth: true` is local development only. It bypasses OIDC and authorization,
requires an explicit loopback address, and still requires explicit keys.

## Decisions

- Single bucket for everything; multi-account routing was considered and
  deliberately dropped.
- Custom state layout instead of the DIY `.pulumi/` layout. Existing DIY state
  migrates per stack: export on the DIY backend, import here.
- No delta checkpoints, no journaling: the capabilities endpoint advertises
  none, so the CLI falls back to full checkpoints.
- Engine events are accepted and discarded; no log retrieval.
- Stack tags, cloud/ESC stack configuration, and per-update configuration or
  environment history are unsupported. Do not use `pulumi config refresh` to
  recover configuration from this backend.

## Out of scope

Policy packs, audit logs, webhooks, teams/RBAC, console UI, ESC, drift
detection, self-service token management.
