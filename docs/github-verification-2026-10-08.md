# Rust migration: GitHub verification

The implementation is available for review in [server PR56](https://github.com/civitaspo/securefix-server/pull/56).
It has not been deployed to the production default branch.
The checks below distinguish live API behavior from the full privileged workflow lifecycle.

## PR CI

[CI run 37778858029](https://github.com/civitaspo/securefix-server/actions/runs/37778858029) passed on implementation commit `1f3fc9626ff47eb0b113f442b41bdebfd4b9d2c3`.
Formatting, 76 Rust tests, Clippy with warnings denied, actionlint, and the aggregate `status-check` succeeded.
The live integration test is ignored by ordinary CI and must be run explicitly with credentials.
The existing Approve Request workflow also succeeded, but it ran the legacy default-branch implementation and is not evidence for the new Rust approval flow.
After both authorization fixes, [CI run 37781458718](https://github.com/civitaspo/securefix-server/actions/runs/37781458718) passed on `cb2c408dbb59418542f4313039569a8809d9496f`, including 79 Rust tests.
The final code also passed 79 local Rust tests, formatting, Clippy, actionlint, and a locked release build.
All three credential-dependent live tests are ignored by regular CI.

## Live API checks

The public [testing-securefix-server](https://github.com/civitaspo/testing-securefix-server) repository was created for isolated fixtures.
The API test added no custom secrets, App keys, production policy capability, or production branch-protection changes.
The test uses an ephemeral authenticated-user token in the local process and writes only to this exact repository.
Its branches and open PRs remain available for inspection; no fixture PR was merged.

The former native commit API probe passed twice.
The second run strengthened stale-head rejection to require a semantic GraphQL rejection, rather than accepting any request error.
That probe and the private commit helper were subsequently removed when Securefix commits returned to the upstream action.
The results below remain historical GitHub API evidence and do not verify the replacement Securefix workflow.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Signed native commit | The shared `createCommitOnBranch` helper accepted GitHub's valid signature, exact parent, and updated ref. | [First fixture commit](https://github.com/civitaspo/testing-securefix-server/commit/bb01e6fdf2676f0f42e376880618c385016fd399) |
| Stale expected head | GitHub rejected the stale `expectedHeadOid`; the branch remained at the first commit. | [Fixture PR2](https://github.com/civitaspo/testing-securefix-server/pull/2), live test assertions |
| Additions and deletions | The next signed commit had the captured parent; the added file's bytes matched and the deleted file returned 404. | [Final fixture commit](https://github.com/civitaspo/testing-securefix-server/commit/9fe2d1a90d09ab70458aedee1ecc9a13ac4de2e3) |
| Stale merge head | REST merge with the earlier SHA returned HTTP 409; PR2 remained open. | [Fixture PR2](https://github.com/civitaspo/testing-securefix-server/pull/2), live test assertions |
| Encoded branch-ref path | The exact `heads%2F...` path used by native Securefix resolved to the expected current head. | [Initial fixture PR1](https://github.com/civitaspo/testing-securefix-server/pull/1), REST ref read-back |

The probe was restricted to this scratch repository and read production main only to exercise the API write guard.
It did not claim that the PR runtime was the active production revision.

## GitHub-signed committer regression

The live fixtures exposed a legitimate-commit rejection in the initial implementation.
GitHub-native commits use REST committer `web-flow`, which was absent from the trusted committer list.
The same representation appears on an existing [Server App commit](https://github.com/civitaspo/dbt-authorized-models/commit/1394a5e3fd2d32a9a3d3c8b641559b22472e45c3).

The fix keeps `web-flow` out of that list.
For this committer only, authorization looks up the exact commit OID and requires `committedViaWeb`, a valid GitHub signature with state `VALID`, and a GraphQL author account matching the REST author and the existing trusted-author policy.
Other committers require a present, trusted committer account, and every commit must still have a verified signature.
The previous fallback to a trusted author when the committer account is absent was removed.
GitHub's [signature verification contract](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) does not guarantee author consent, and verified records persist after signing-key changes.
This conservative rejection does not depend on reproducing account-removal behavior against a live account.
Missing, mismatched, or invalid identity and signature fields fail closed.
GitHub documents [credential-bound native authorship](https://docs.github.com/en/graphql/reference/commits) and the [GitHub signing-key signal](https://docs.github.com/en/graphql/reference/git).

The ignored read-only regression passed against both fixture commit `9fe2d1a90d09ab70458aedee1ecc9a13ac4de2e3` and Server App commit `1394a5e3fd2d32a9a3d3c8b641559b22472e45c3`.
It exercises the same signature lookup and trusted-committer predicate used by approval, merge, and policy checks.
This read-only probe does not establish App token permissions or full request provenance.

```sh
cargo test --locked --bin securefix live_known_github_web_flow_commits_match_trusted_author_identities -- --ignored --nocapture
```

Provide `SECUREFIX_LIVE_TEST_TOKEN` through the process environment.
The regular HTTP regressions cover identity mismatches, absent metadata, non-GitHub signatures, and successful PR authorization.
A separate same-model reviewer found no material blocker in this change.

## Deployment checks still required

Full approval, merge, release, settings activation, and Securefix intake/provenance/artifact flows remain unverified against GitHub for the Rust implementation.
Authenticated-user commits do not prove Server App signatures, installation scopes, machine-user review permissions, GPG signing, or immutable release publication.

Production main was `de2c66e03e2c63cdd5dddec0229e948e4f442236` during these checks.
Its `main` environment permits only the `main` branch, and label events execute the default-branch workflow.
It does not yet contain `policy.json`; a pre-deployment call to Rust `securefix validate-event` stopped at that missing policy before processing the event or creating a token.
Running PR code as an active privileged runtime would violate the accepted revision and environment boundaries.
No production ruleset, environment restriction, runtime check, or client pin was changed to enable this probe.

The operator reports installing the Client App, Server App, and Renovate for the scratch repository.
The repository secret metadata confirms `SECUREFIX_CLIENT_PRIVATE_KEY` was registered on 2026-10-08.
These provisioning steps do not activate the Rust runtime or add the scratch repository to production policy.
The [Client App credential probe](https://github.com/civitaspo/testing-securefix-server/actions/runs/37781890589) passed.
It builds the reviewed Rust test at server commit `678e10c6d968b17cb967b5a3589f40f7aae6cf65` without credentials and downloads the exact artifact ID in a separate job.
That job authenticates Client App ID `3872492`, requests only `Metadata: read`, and scopes the token to `testing-securefix-server`.
The Rust probe confirmed `/installation/repositories` returned exactly this repository and its identity lookup succeeded.
The token action revoked the token after the job.

The [initial attempts](https://github.com/civitaspo/testing-securefix-server/actions/runs/37781078478) caught a PEM value with lost newlines and an unnecessary `Contents: read` request unsupported by the installation.
The operator restored the raw PEM, and the probe was reduced to its required metadata permission.
No App permissions were expanded.
The [manual probe workflow](https://github.com/civitaspo/testing-securefix-server/blob/b0db14244026157c52d9c6eee18c42b28e78feb7/.github/workflows/client-app-smoke.yml) and ignored Rust test remain available to rerun.
The Server installation and its full requested permissions still require App-authenticated lifecycle verification during staging.

## Prebuilt runtime distribution follow-up

The runtime now has a dedicated main-push producer and a SHA-keyed GitHub Release loader.
Normal operations reuse the verified archive; they do not compile Rust.
The producer's publication job verifies the same archive before extracting its executable.
Seven new Rust tests cover exact asset identity/digest, matching draft recovery, published idempotent retry, stale runtime rejection, and non-404 failures.
The complete local suite passes 86 tests with three credential-dependent tests ignored; formatting, warnings-denied Clippy, and pinned actionlint pass.
Structural tests check immutable IDs, caller permission grants, source identity, credential separation, and fail-fast verification before extraction/execution.

The [runtime distribution smoke run](https://github.com/civitaspo/testing-securefix-server/actions/runs/37785745337) succeeded on scratch main `742c9eb4764310ada2ed2b36ba97411cc59ec365`.
It attested a harmless source-SHA text archive using the same pinned official action, transferred that archive by immutable artifact ID, verified it in the separate publisher job, published it only to scratch, and downloaded/verified it in a read-only job.
The runner's `gh` was version 2.102.0; the initial run also confirmed the certificate constraints with 2.101.0.
Both certificate source and signer digests matched the actual `job.workflow_sha`.
Verification rejected different source and signer SHA values, a different signer workflow, repository and source ref, and modified archive bytes.
The expected source/ref failures explicitly reported the actual certificate values in the Actions log.
Using only the scratch repository's contents-read/attestations-read `GITHUB_TOKEN`, the run also downloaded `cli/cli`'s public Linux release archive and verified its build attestation, proving public cross-repository reads without an App or PAT.

The [initial smoke run](https://github.com/civitaspo/testing-securefix-server/actions/runs/37785390380) passed the exact-source and rejection checks but failed the cross-repository attestation step because the chosen checksum file had no SLSA build attestation.
The successful run used the attested binary archive instead.
No extra App permissions, secrets, or production settings were used.
The scratch archive contains no executable and exercises GitHub distribution/provenance, not the full privileged runtime.
The production Rust publisher's real asset upload and main-push producer still require deployment validation; these tests do not establish full approve/merge/release/settings E2E.
Follow the [migration sequence](migration.md) after review and deployment; the API probe does not replace those lifecycle tests or activation attestation.

## Upstream Securefix reuse follow-up (2026-10-09)

Securefix intake now uses the pinned upstream v0.6.3 `prepare`, `commit`, and `notify` actions at `1b770a7af0ec5e04517295b4e14c4b451359d550`.
Rust checks the label and active repository capability before preparation, then validates source-run provenance and the prepared destination before committing.
Only six non-secret prepared fields enter the Rust process.
The runtime archive includes `securefix-config.yaml`, which restricts default-branch release requests to the seven release-capable clients and their same-repository `release/next` destination.
The attested executable and configuration remain outside the artifact extraction workspace.
The private ZIP parser and native Securefix commit helper are removed.

The final local suite passes 81 Rust tests, with three credential-dependent tests ignored by ordinary CI.
Formatting, warnings-denied Clippy, pinned actionlint, a locked release build, and CLI command inspection pass.
The local macOS build emitted a host-toolchain warning about an unavailable LLVM library during optional stripping; it exited successfully and both CLI help surfaces executed successfully.
The new HTTP-fixture tests exercise the complete Rust post-prepare gate for both in-progress and completed-failed client runs, an advanced same-repository PR head, and release source provenance.
Workflow paths may be bare or use one nonempty reference suffix; unknown filenames, empty suffixes, and multiple suffix delimiters are rejected.
The release fixtures check the caller revision, referenced workflow revision, default-branch ancestry, and restricted PR creation options.
Structural tests cover upstream action ordering and pins, credential separation, notification conditions, and configuration packaging and agreement with policy capabilities.
An independent same-model security review found no remaining proven security or correctness issue; the separate comment review found no required comment removal.

The actual pinned distributed action ran locally with `action: validate-config`.
It accepted the restored configuration and rejected an `entries: not-an-array` fixture with a schema error.
These validation runs used no GitHub credential and performed no GitHub write.
The pinned distributed commit helper was separately executed with local API doubles: applying A's file content after observing head B succeeded, advancing B after observing A was rejected by the simulated non-force ref update, and setting `baseSHA: A` rejected an already advanced B.
This executes the distributed helper, not the whole action on GitHub; it does not establish latest-action E2E or a security exploit.
The reproduction, observed results, and upstream repair instructions were delivered separately under `/private/tmp/securefix-action-stale-head-fix-20261008/`.
No upstream Issue or PR was posted.

The replacement ignored live test passed against [scratch PR4](https://github.com/civitaspo/testing-securefix-server/pull/4).
It created head A, advanced the branch to B, waited for the PR API to reflect B, and required an HTTP 409 response when merging with A's SHA.
The PR remained open at B (`fbf5631f1a3fb04fcaec24bc929a02e96ff9d609`); no fixture was merged and scratch main was unchanged.
An initial attempt already received 409 but failed its immediate PR read-back assertion; subsequent inspection of [scratch PR3](https://github.com/civitaspo/testing-securefix-server/pull/3) confirmed it remained open at the advanced head.
The test now waits with a bounded retry for GitHub's PR head representation before exercising stale-head rejection.

`approve-pr-action` v1.0.0 at `a8fdc60ab4d9b446694140534bbcc71c29fb499c` has no expected-head input.
The Rust approval implementation remains because this upstream version cannot preserve owner authorization of a captured head when a later head arrives before its lookup.
See the [integration decision](adr/0005-upstream-securefix-protocol.md).
Full privileged workflow E2E, including replacement Securefix intake and cleanup, still requires deployment under the accepted production revision and environment restrictions.

## Branches, CLI installation, and staging CI follow-up (2026-10-09)

The seven exact Securefix client repositories now have branch patterns `**` for both source and push branches.
The pinned distributed action accepted this configuration with `validate-config` locally, without credentials or writes.
Rust still rejects a different destination repository and direct default-branch pushes.
Ordinary PR CI can update only its own source branch; a trusted default-branch release-PR workflow can choose any non-default destination after the release capability and provenance checks.
The product release commands retain `release/next` as their working branch convention.

All operational jobs install the supplied runtime through one `install-cli` composite action and invoke `securefix` on `PATH`.
Runtime, policy, configuration, and settings downloads live under `runner.temp`, outside client checkout and artifact extraction.
The [checkout-free action prototype](https://github.com/civitaspo/testing-securefix-server/actions/runs/37802713895) passed at scratch commit `948b88e4b948a521434f4e9320d8732ed7abae5a`.
Its native `$/` reference resolved to the defining workflow's repository and running commit.
GitHub documents that resolution for [reusable workflows called from another repository](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-using-an-action-in-the-same-repository-as-the-workflow-at-the-running-commit-recommended).
Pinned actionlint v1.7.12 does not recognize this new syntax; CI suppresses only its specific diagnostic for `$/.github/actions/install-cli`, alongside its existing `job.workflow_sha` compatibility diagnostic.
Rust structural tests require the known installer path and immutable runtime source rather than accepting arbitrary unpinned actions.
The final local suite passes 82 Rust tests, with three credential-dependent live tests ignored.
Formatting, warnings-denied Clippy, actionlint with these two compatibility diagnostics excluded, and whitespace checks pass.
An independent same-model security review found no remaining proven blocker; the comment review required no deletions.
The release-PR and provider-build workflows install the CLI after their PATH-changing tool setup so subsequent commands resolve the installed executable.

The dedicated [scratch testing workflow](../.github/workflows/testing-securefix-server.yml) builds a reviewed server SHA without custom secrets and uploads one immutable same-run artifact.
Its separate probe job checks CLI discovery, mode `755`, valid and invalid policy, the upstream configuration, and an exact-scratch metadata-only Client App token.
It creates no Release and needs no additional secret or cross-repository artifact credential.
Production runtime publication is now an owner-only manual dispatch on server main.
The exact-current-main guard remains: operations stop after main advances until that stable revision is promoted and caller pins are updated.
Full privileged lifecycle E2E remains a deployment check.
