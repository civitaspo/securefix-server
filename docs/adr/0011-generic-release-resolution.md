# Generic package release resolution

Status: accepted for read-only stable metadata resolution, byte integrity, and
the single-workflow publisher-proof contract described below. The source also
contains a separate native-package producer and publisher path; it is not yet
scratch-qualified. No operational caller is wired to the verified result;
broader D01 remains open.

## Context

The instance-configuration design selects the implementation with a literal
full-SHA workflow or action pin and accepts compatible package versions with a
trusted `semver::VersionReq`. Those are separate facts: a version range cannot
select executable code, and a pinned source revision alone does not prove that
the release asset was produced by an authorized workflow.

The existing runtime publisher and active descriptor use the legacy runtime
archive contract. The native-package publisher has a separate release contract;
it does not change the legacy runtime archive schema or add an operational
consumer to that flow. A generic package resolver needs to establish
the bounded GitHub metadata relationship that a later caller can use without
enumerating releases or silently choosing a fallback.

## Decision

`package::resolve_release` accepts four explicit inputs: a trusted publisher's
canonical repository name and numeric ID, the already selected full lowercase
implementation SHA, an expected component/platform/asset name, and an accepted
`VersionReq`. A successful resolution makes four read-only GitHub GET
requests; any failed check stops before later requests:

1. Read the publisher repository and require the returned full name and ID to
   match the trusted input.
2. Read `Cargo.toml` with `ref` set to the exact implementation SHA. Require
   the expected file identity, base64 encoding, matching declared and decoded
   sizes within 64 KiB, valid UTF-8/TOML, and a canonical stable package
   version without prerelease or build metadata. Require that version to match
   the accepted range.
3. Read exactly `v<version>` and require a lightweight commit ref whose target
   is the implementation SHA.
4. Read the release for that exact tag and require its tag and target commit to
   match, the release to be published, immutable and stable, and exactly one
   uploaded asset. The display name is not part of release identity. The asset
   must have the caller-selected name, a positive ID, a positive size no
   greater than 512 MiB, and a canonical lowercase `sha256:` digest.

The first contract equates implementation SHA and source SHA. It rejects
annotated tags and releases with multiple assets; supporting either requires a
separately bounded proof design. Repository contents, Git refs, and release
metadata are read using GitHub's REST interfaces for [repository
contents](https://docs.github.com/en/rest/repos/contents#get-repository-content),
[Git references](https://docs.github.com/en/rest/git/refs#get-a-reference),
[releases](https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name),
and [release assets](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).

`resolve_release` returns only publisher, source, implementation, version, tag,
release ID, and expected asset identity/size/digest claims. It does not fetch
asset bytes or establish their provenance. `download_release_asset` repeats the
same four metadata checks, then requests the exact asset ID from the validated
repository using GitHub's release-asset endpoint. It bounds the response by the
declared size, requires the returned length to match, and compares the bytes'
SHA-256 with the immutable-release API digest. The existing API download helper
requests the raw asset representation and enforces its HTTPS redirect-host
allowlist without forwarding the API bearer token.

`DownloadedAsset` remains unqualified content data. `package::download_verified_release`
composes the metadata and digest checks with the official `gh attestation verify`
command over the downloaded asset and repository-bound public bundle. Its
caller supplies the trusted publisher workflow path and branch. The verifier
requires the OIDC issuer, SLSA v1 predicate, GitHub-hosted runner, exact source
SHA/ref, and exact signer workflow/digest. The Rust validator then checks the
single statement subject against the asset name and actual SHA-256. It takes
run ID and attempt from the verified certificate's `runInvocationURI`—not from
producer-controlled SLSA invocation metadata—and fetches that exact REST run
attempt. The run must be successful `workflow_dispatch` for the same repository,
workflow path, source commit, and configured branch. The result is a distinct
`VerifiedPackage` carrying the asset and publisher run identity. A package
consumer that may execute bytes must use this result, never
`DownloadedAsset`.

This contract matches the observed in-repository `workflow_dispatch` publisher.
It does not infer that a workflow ref equals the release tag, nor accept a
reusable-workflow or composite publisher without evidence for that invocation
form. Repository names, IDs, workflow paths, and branches remain explicit
trusted inputs. The code makes no repository-administration query and changes
no credential scope. The expected asset platform and component also remain
caller-selected; the resolver checks the single asset name.

The resolver does not load legacy `Policy::active()` or `config::trusted()`,
read an active descriptor, enumerate latest releases, choose a version, or
write GitHub state. It remains separate from the native-package publishing
writer and has no operational caller. Repository settings, active control, and
legacy runtime publication are unchanged.

## Native package producer and publisher

`.github/workflows/native-package-build.yml` is the owner-dispatched producer.
It builds and tests the selected source with read-only repository access, uploads
only the raw executable, then creates a separate repository-bound attestation.
The build job has no package writer token, signing key, or candidate-provided
credentials.

`.github/workflows/publish-native-package.yml` builds its publisher host from
the exact protected workflow revision in a read-only job. In a separate `main`
environment job, that host validates the requested producer run, its exact
artifact and attestation, and the selected stable or scratch destination using
read-only GitHub access before the workflow mints an App token. The token grants
only `contents:write` to the selected destination repository. When the exact
package is already published as an immutable release and its recorded producer
and publisher evidence match, the workflow skips token creation. The host
rechecks the source, asset bytes, release state, and recovery evidence before
writing.

This publisher implementation has local contract tests but is not yet
scratch-qualified. Its presence does not qualify a release, wire a package
consumer, select a package version, change the active runtime, or activate a
caller. Those steps remain subject to the source and evidence gates in the
deployment workflow.

## Consequences and limits

The resolver and mock API tests prove the local request paths, metadata
rejection behavior, bounded download, and byte length/digest comparison. A
separate read-only probe against public GitHub APIs resolved and downloaded the
existing `civitaspo/securefix-server` v0.2.44 legacy runtime archive as data:
publisher ID `1250079425`, implementation/source
`1b35591e74eeae8fe848d16c6fcae0ba8fb75f6c`, release ID `418770067`, asset ID
`660228208`, 4,264,106 bytes, SHA-256
`d40309b8b574947bd9900e6996a804b38950749e7cf799161bec534cf68061b8`. The probe
used `cargo run --locked` with the repository lockfile and a temporary harness
entry. Its local logs are `/private/tmp/securefix-package-probe/probe.log` and
`/private/tmp/securefix-package-probe/probe-build.txt`; they are not persisted CI
evidence. The bytes remained in memory and were not written, executed, extracted,
or unpacked. This establishes only that this existing legacy archive's release
metadata and downloaded bytes fit the resolver's metadata and data-integrity
contract. It does not qualify the generic package format or publisher path,
nor any bounded publication adapter that a later transition may prove
necessary.

A local Rust integration probe passed the new verified path for the existing
immutable v0.2.44 Server runtime archive. It re-resolved and downloaded the
asset, verified its public attestation, matched the exact `publish-runtime.yml`
source and signer, checked successful run `39481325307` attempt `1`, and
returned the expected 4,264,106-byte SHA-256 subject. The archive remained data;
it was not executed or unpacked. The focused Rust package tests passed 13/13.
This is source inspection and one local public-release probe, not hosted
candidate qualification or a production caller test. The verifier has no
operational consumer yet, and protocol identity is not in `VerifiedPackage`.
Other publisher forms, a scratch prerelease route, and pre-execution checks in
hosted scratch remain unqualified. Do not describe a `ResolvedRelease` or
`DownloadedAsset` as attestation-qualified or executable. Candidate qualification
and the ordinary reviewed promotion flow are still required before a production
caller can depend on a new package path.
