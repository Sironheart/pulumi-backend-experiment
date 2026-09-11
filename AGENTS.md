# AGENTS

Pulumi Cloud-compatible backend in Go. Single S3 bucket, generic OIDC auth
(any SSO provider), KMS envelope secrets. GoReleaser publishes binary archives
and a multi-architecture container image built with ko.

## Layout

- `cmd/pulumi-backend` — entrypoint
- `internal/config` — YAML config: issuer, clientId, signingKey, bucket, region, kmsKeyArn, noAuth
- `internal/authn` — OIDC validation (go-oidc); backend + update tokens (golang-jwt, HS256)
- `internal/store` — S3 state store, conditional-write locks/leases
- `internal/secrets` — KMS envelope crypter
- `internal/api` — HTTP handlers, Pulumi Cloud API subset

## Pulumi CLI wire contract — do not break

Verified against real CLI 3.261:

- Update-scoped calls authenticate with `Authorization: update-token <jwt>`
  (scheme `update-token`, not `token`).
- CreateStack must return a JSON body; an empty 204 fails the CLI with
  "unexpected end of JSON input".
- Export on a fresh stack returns 200 `{"version":3,"deployment":{}}` — the CLI
  fetches the current deployment on every operation and treats 404 as fatal.
- StartUpdate responds `journalVersion: 0` → CLI never calls `/journalentries`.
- Capabilities advertises none → CLI uses full checkpoints, never
  `checkpointdelta`.

## Testing

- Handler tests: in-memory fakes. AWS integration: floci via testcontainers-go
  (S3 conditional writes, KMS, STS all covered); LocalStack only if floci gaps.
- OIDC units use in-process httptest stubs; `TestValidateAgainstKeycloak` runs
  against a Keycloak container (stillya/testcontainers-keycloak).
- TDD for behavior changes.

## Conventions

- `--config` flag falls back to `PULUMI_BACKEND_CONFIG` env, then `config.yaml`.
- No multi-account support: one bucket, one KMS key, ambient credentials.
- `noAuth: true` disables OIDC and accepts any Pulumi request (identity
  from the presented token). Local runs only.
