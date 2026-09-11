# Pulumi Backend

Pulumi Cloud-compatible HTTP backend for the Pulumi CLI. All state lives in a
single S3 bucket. Written in Go, shipped as a container image.

## Architecture

- The CLI talks the Pulumi Cloud REST API to this service (`pulumi login https://...`).
- **State**: one S3 bucket, custom key layout `<org>/<project>/<stack>/…`
  (checkpoints, update records, history).
- **Locking**: S3 conditional writes (`If-None-Match: *`) with expiring leases;
  stale locks are breakable. Previews run lock-free.
- **Secrets**: service-side envelope encryption via a single KMS key
  (`GenerateDataKey` + AES-256-GCM). Optional — without `kmsKeyArn` the
  encrypt/decrypt endpoints are disabled and stacks use their own secrets
  provider.

## Decisions

- Single bucket for everything; multi-account routing was considered and
  deliberately dropped.
- Custom state layout instead of the DIY `.pulumi/` layout. Existing DIY state
  migrates per stack: export on the DIY backend, import here.
- No delta checkpoints, no journaling: the capabilities endpoint advertises
  none, so the CLI falls back to full checkpoints.
- Engine events are accepted and discarded; no log retrieval.

## Out of scope

Policy packs, audit logs, webhooks, teams/RBAC, console UI, ESC, drift
detection, self-service token management.
