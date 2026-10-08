# Separate provider builds, signing, and publication

Client source and release configuration can execute code during a build.
The provider build therefore runs with no custom secrets and produces a closed set of server-defined assets.
It does not execute client GoReleaser configuration or hooks.
The supported target matrix and asset names preserve the existing Sigma provider contract.

The signer accepts only a bundle from the expected producer and validates its names, archive entries, sizes, manifest, and recomputed checksums.
It receives the signing key and no publication credential.
The publisher receives a scoped publication token and no signing key.
Artifacts are selected by immutable ID and source-run identity.

Publication retries recover the same draft identity.
Existing published assets are compared and never overwritten.
Manual retries select a merged release PR rather than an arbitrary commit SHA.
