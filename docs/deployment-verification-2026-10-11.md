# Rust migration: deployment verification

The native Rust migration is deployed and operational. This report records completed checks through runtime v0.2.10 on 2026-10-11; it is evidence for specific revisions, not a guarantee for future changes. The [initial API report](github-verification-2026-10-08.md) and [former implementation report](archive/merge-verification-2026-10-08.md) remain historical records.

## Native runtime and caller deployment

[PR70](https://github.com/civitaspo/securefix-server/pull/70) introduced the reviewed native deployment. The [pre-publication candidate run](https://github.com/civitaspo/securefix-server/actions/runs/38007188524) exercised signed writes, automatic merge, stale-head rejection and client artifact validation against testing-securefix-server without creating a candidate Release. The [published-client run](https://github.com/civitaspo/securefix-server/actions/runs/38008201517) verified the released binary's digest and attestation. [Settings reconciliation](https://github.com/civitaspo/securefix-server/actions/runs/38011298056) completed for the configured settings fleet.

Runtime tags and Release names use SemVer, including `v0.2.0-pre.1` for prereleases. Published archives are bound to their exact source revision and publisher attestation. Temporary bootstrap branches and deployment allowances were removed; historical SHA-named runtime releases/tags were cleaned up.

[PR82](https://github.com/civitaspo/securefix-server/pull/82) migrated dependency updates to Renovate and fixed sha2 0.11 digest encoding while preserving lowercase, zero-padded SHA256 strings. The strict Renovate config validator, checksum regression and required CI passed. The [candidate run](https://github.com/civitaspo/securefix-server/actions/runs/38130342713) successfully used that candidate binary with the live scratch approval fixture and read-only credentials. [v0.2.10 publication](https://github.com/civitaspo/securefix-server/actions/runs/38130661941) and [automatic distribution to all ten callers](https://github.com/civitaspo/securefix-server/actions/runs/38130776560) succeeded. Dependabot PRs #57–#62 were closed.

The first dependency-update PR and automerge produced by this repository's new Renovate configuration had not been observed at the time of this report. Renovate's existing sensitive-path exemption remains separate from trusted-committer membership.

## Approval and release-PR refresh

[PR81](https://github.com/civitaspo/securefix-server/pull/81) fixed automatic approval after the default branch advances beyond a PR's recorded base, while retaining caller ancestry, exact reusable pins and current-head authorization. Managed release-PR updates already synchronize their metadata; redundant release-branch push Sync was removed from generated wrappers, and existing redundant Sync workflows were disabled. The [candidate capture](https://github.com/civitaspo/securefix-server/actions/runs/38102313651) passed before publication.

After v0.2.9 distribution, both refreshed release PRs had successful current-head checks and automatic bot approval for that same head:

| Repository / PR | Verified head | Evidence |
| --- | --- | --- |
| testing-securefix-server #105 | `907ad4a4ca13a0605d7233fa382707131ba19f9f` | [Automatic approval CI](https://github.com/civitaspo/securefix-server/actions/runs/38103218439), [exact-head review](https://github.com/civitaspo/testing-securefix-server/pull/105#pullrequestreview-5481541312); all eight checks succeeded |
| terraform-provider-sigma #174 | `49b5fd008a982425feae0b85d918bf0c8b61dded` | [CI](https://github.com/civitaspo/terraform-provider-sigma/actions/runs/38103395103), [policy check](https://github.com/civitaspo/securefix-server/actions/runs/38103459749), [exact-head review](https://github.com/civitaspo/terraform-provider-sigma/pull/174#pullrequestreview-5481545415); all checks succeeded except the expected failure-only aggregate skip |

These results include checks on the resulting PR heads, not only the producer workflow or server write. Testing PR #105 was left open during this verification. An owner command's rocket reaction acknowledges intake; completion is established by the resulting review, check or merge.

## Normal Sigma release and Terraform Registry

The owner subsequently merged Sigma [PR174](https://github.com/civitaspo/terraform-provider-sigma/pull/174), producing commit `8acde9dabec31fcfa2ef9f65adea59abf4bd2c7b`. The normal [Release Tag workflow](https://github.com/civitaspo/terraform-provider-sigma/actions/runs/38104079382) and [server release workflow](https://github.com/civitaspo/securefix-server/actions/runs/38104382044) both succeeded. The tag `v0.2.3` resolves to that merge commit; no manual republication or alternate publication path was used.

[GitHub Release v0.2.3](https://github.com/civitaspo/terraform-provider-sigma/releases/tag/v0.2.3) is immutable and contains 13 platform ZIPs, the Terraform manifest, SHA256 checksums and the GPG signature. [Terraform Registry 0.2.3](https://registry.terraform.io/providers/civitaspo/sigma/0.2.3) was registered at `2026-10-11T02:14:03Z`, including 64 documentation entries. Its Linux amd64 download metadata points to that GitHub Release. Downloading the ZIP and hashing its bytes matched the Registry checksum `430f2db52908ae352f424e04c7a104305d992401e932f4166e2f5a563e3e43a6`.
