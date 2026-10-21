# Native request producer proof

Status: scratch-qualified for the single U05a `workflow_dispatch` policy-check
fixture described below. D01 remains open for generic published Client source,
`pull_request_target`/`issue_comment` callers, and release qualification.

## Context

Run metadata and request artifacts can be self-asserted by a caller. Workflow
references, display names, or canonical YAML at a claimed SHA do not prove the
expected reusable producer ran. PR-target runs can have an empty
`pull_requests` array, and run-level references can mention a skipped reusable
call. Native artifact attestations may bind manifest bytes to both caller and
reusable revisions, but this split must first be demonstrated in scratch.

## Proposed contract

One immutable, full-SHA-pinned Client request-capture reusable workflow runs in
the Client repository context. Invoked by Client event wrappers, it constructs
a fixed, bounded request manifest from supported GitHub event/run facts and
attests it at a fixed path. It accepts no caller-selected subject path, digest,
predicate, or manifest content. It checks out and executes no PR or other
untrusted code. Exactly one fixed job in this reusable workflow has signing
permissions and creates the manifest. The caller and reusable workflow both grant only
`contents: read`, `id-token: write`, and `attestations: write`; do not add
`artifact-metadata: write` unless the scratch probe proves plain file
attestation needs it with storage records disabled.

The trusted job carries the `actions/attest` local bundle beside the manifest
in its short-lived Actions artifact. Current Server publisher workflows and
`.github/workflows/actions.lock` agree on these full pins and versions:
`actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6` (`v4.2.2`) and
`actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`
(`v4.6.2`). Local bundle verification needs no Server App or
`attestations:read` scope; the artifact is transport, not proof.

The receiver reuses `gh attestation verify` and the isolated local-bundle CLI
path in `src/control_commands.rs`, without `GH_TOKEN` or `GITHUB_TOKEN`. Supply
the exact repository, reusable `--signer-workflow` and `--signer-digest`,
expected OIDC issuer and SLSA predicate, and hosted-runner restriction. Request
JSON, hash the bounded manifest bytes, and strictly compare verified claims
with the authenticated Actions run. Cap verifier time at 30 seconds and JSON
at 1 MiB; terminate on timeout and fail closed. Reuse GitHub CLI verification;
do not implement a custom JWT/OIDC parser.

Trust `verificationResult.signature.certificate` and verified timestamps for
signer/run identity. Do not trust `statement.predicate` as producer proof; the
workflow can write it. The CLI verifies the subject digest against the file,
so only the trusted reusable may choose that fixed file.

Check these certificate fields:

- `buildConfigURI` / `buildConfigDigest`: caller `workflow_ref` /
  `workflow_sha`, the top-level workflow path and file revision. Require the
  expected path and check canonical YAML at that digest.
- `buildSignerURI` / `buildSignerDigest` and SAN: reusable
  `job_workflow_ref` / `job_workflow_sha`; require its exact path and immutable
  source revision.
- `sourceRepositoryURI`, `sourceRepositoryIdentifier`,
  `sourceRepositoryOwnerIdentifier`, and `githubWorkflowTrigger`: repository
  identity and event. `runInvocationURI` must match API run ID and attempt.
  The certificate has no job ID; retain the one-signing-job constraint.
- `sourceRepositoryDigest` and compatibility `githubWorkflowSHA` map to OIDC
  `sha`, the event source commit. They are not the caller workflow SHA. Keep
  PR head/base facts separate: for `pull_request_target`, the PR head is the
  untrusted change identity while the caller workflow is base-defined; for
  `issue_comment`, bind the caller to the default-branch workflow revision.
  Infer neither from `pull_requests[]`.

The signed manifest also carries a capture-time `NativeAuthoritySnapshot` for
the Server instance. Its repository and root-relative config path are untrusted
locators, not policy selectors: the Server must first match both to its
authenticated execution repository, strict instance config, and explicit CLI
config path, then reconstruct and compare the full snapshot before processing
the producer artifact. The Server execution workflow ref, SHA, and operation
role must also match the snapshot's protected default-branch wrapper. The
snapshot and role binding have local tests only; exact hosted Server
runtime-artifact ID/digest/source mapping remains unqualified.

## Qualification gate

Use a reviewed, signed, immutable development source revision of the Client
request-capture reusable. Call it cross-repository from the
`testing-securefix-server` event wrappers pinned to that exact fixture SHA;
production Server `main` remains untouched. Before any scratch mutation,
review the exact wrapper deployment route. Record the Client source SHA, the
fixture reusable SHA, and the scratch wrapper source SHA. The scratch event
wrappers are fixture listeners only; add no production listener and use no
production credential. Use only a static sentinel
manifest: no secrets, App tokens, or PR/client code execution. The probe must cover positive
`pull_request_target` and PR `issue_comment` calls, self-attestation with fake
job/step names (reject signer), and a skipped reusable plus forged same-name
artifact (reject absent/wrong attestation). Use separate runs for cases:
`upload-artifact` v4 forbids duplicate artifact names in one run. Record run
URLs and attempts, artifact IDs, verified JSON, and rejection logs. D01 remains
open until this evidence is reviewed.

Before the request-producer probe, evidence was limited to single-workflow
release attestation:
`/private/tmp/securefix-c80e-v0244-verified.json` (verified result),
`/private/tmp/securefix-c80e-v0244-runtime.tar.gz` (opaque archive),
`/private/tmp/securefix-c80e-v0244-attestations.jsonl` (local bundle), and
`/private/tmp/securefix-c80e-native-producer-proof.md` (investigation report).
It did not qualify reusable caller/signer claims or Client requests.

Primary references: [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc),
[reusable workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations),
[Fulcio claim mapping](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md),
[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify),
[artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
and [`actions/attest`](https://github.com/actions/attest).

## Scratch evidence (2026-10-21)

The scratch caller was `.github/workflows/policy-check.yml` on
`testing-securefix-server` main `0fbe835ef9b27f36f74a5bf27d9f3d6459de38f0`.
The source-bound Rust candidate was built from
`961ffff5ab30be4a0197c64c9a4170515b787f5f` by
[run 39563689101](https://github.com/civitaspo/securefix-server/actions/runs/39563689101)
as artifact `12328813435` (SHA-256
`3e8ff5b90550f70308f240fde77d058aeb37e700211db044a1e66874a7196ca6`). The
attestation signer was the distinct reusable-workflow commit
`93f0c7b4c35e9946a899c2fdf5b09529894ac067`; the workflow-only fix did not
change or rebuild the Rust candidate.

Producer [run 39564989587](https://github.com/civitaspo/testing-securefix-server/actions/runs/39564989587)
created artifact `native-request-proof`, ID `12328924468`, SHA-256
`037069a2d049e123c2540bf898ef1aaea8997a048b1861a6c9eb2eb452905bda`. It
contains a 746-byte manifest and the 11,271-byte local bundle. The manifest
binds producer run/attempt `39564989587/1` and PR #365 head
`744dee8dc68da2aa8a8fa4271e9f37b7bedfba76`. Consumer
[run 39565253920](https://github.com/civitaspo/testing-securefix-server/actions/runs/39565253920)
verified that bundle and published check `securefix-native-request-policy-check`
ID `119106008516` (GitHub Actions App 15368 (scratch `GITHUB_TOKEN`)) on the captured head.

Signed commit `d7d9ab8c538fd853dc7b29d6ae5a9d2fb3527ae0` advanced the same PR
after capture. Replaying the same artifact in
[run 39565408082](https://github.com/civitaspo/testing-securefix-server/actions/runs/39565408082)
failed with `native request PR is closed, retargeted, or has a different head
or identity`; independent check readback found no check on the new head and
exactly one check on the captured old head.

An earlier producer run `39564186380` omitted the local bundle because the
workflow treated `bundle-path` as an action input. Consume run `39564377455`
failed on the missing file. The corrected workflow copies the action output in
revision `93f0c7b`; the successful consume reuses the unchanged Rust candidate.
This probe used `workflow_dispatch`. It did not exercise `pull_request_target`
or `issue_comment`, a published Client release, the complete instance config,
full request history, Client signature enforcement, or owner-review approval.

