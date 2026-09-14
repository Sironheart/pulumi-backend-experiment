# Release verification

The release workflow builds platform archives, SPDX SBOMs, checksums, a
multi-architecture container image, and its digest list.

## Verification

Download the archive, its SPDX SBOM, and `checksums.txt` from the same trusted
release page. Verify their checksums before use:

```sh
sha256sum --check --ignore-missing checksums.txt
```

Checksums detect accidental corruption but do not authenticate the publisher.
Use a trusted Forgejo release URL and protected tags when obtaining artifacts.

## Container verification

Use the immutable image reference from `digests.txt`, not a mutable tag such
as `latest`:

```sh
image='forgejo.siron.casa/sironheart/pulumi-backend-experiment@sha256:<digest>'
docker pull "$image"
```

The OCI image is built from the digest-pinned Chainguard static base image.

## Future hardening

Self-managed Cosign signing is intentionally deferred until a production key
pair and its committed public verification key are provisioned. At that point,
sign the checksum manifest and image digest, make releases verify that the
public key matches the private release secret, and publish the signature
bundles with each release.

## Dependency updates

Renovate updates Go modules, Mise tool versions, action pins, and the release
base-image digest. A self-hosted Renovate instance must permit its `mise` safe
execution so it can regenerate `mise.lock`; see the
[Renovate Mise manager documentation](https://docs.renovatebot.com/modules/manager/mise/).
