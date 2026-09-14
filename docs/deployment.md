# Deployment hardening

This backend stores all state in one S3 bucket. Treat that bucket and the
backend's token and secrets keys as production credentials.

## S3 bucket

- Enable S3 Block Public Access and Bucket owner enforced object ownership.
- Require TLS with a bucket policy and grant the runtime IAM role only the
  `ListBucket`, `GetObject`, `PutObject`, and narrowly scoped delete actions
  needed for this bucket's state prefix.
- Enable versioning and default SSE-KMS encryption. The backend's application
  encryption protects Pulumi secret values; S3 encryption protects the rest of
  the state and object metadata at rest.
- Record CloudTrail S3 data events, alert on access-policy changes and failed
  access, and test a version-recovery procedure before relying on the service.
- Use an independent backup account or destination and regularly test restore.

See [AWS S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
for the corresponding AWS controls.

## Service boundary

- Terminate TLS in a trusted reverse proxy or configure TLS directly on the
  service. Do not expose `noAuth: true` outside loopback.
- Store `signingKeys` and `secretsKey` in a secret manager, not in a config
  file or image. Rotate token signing keys by adding a new key, making it
  active, waiting for the previous token lifetime, then removing the old key.
- Grant deployment and CI identities only the credentials they need. Keep
  release credentials separate from runtime AWS credentials.

## Token lifetime and revocation

Backend and update tokens carry the caller's group snapshot until they expire.
There is no per-token revocation or server-side token tracking. Keep
`tokenTTL` short enough for group-membership changes (the default is 24 hours).

For an emergency revocation, remove the affected signing key from
`signingKeys` and restart the service. That invalidates every backend and
update token signed with that key; rotate to a new active key first if ongoing
sessions must continue. Normal key rotation retains old keys until their token
lifetimes expire, while emergency revocation intentionally does not.
