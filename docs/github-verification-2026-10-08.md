# Rust migration: GitHub verification

The implementation is available for review in [server PR56](https://github.com/civitaspo/securefix-server/pull/56).
It has not been deployed to the production default branch.
The checks below distinguish live API behavior from the full privileged workflow lifecycle.

## PR CI

[CI run 37778858029](https://github.com/civitaspo/securefix-server/actions/runs/37778858029) passed on implementation commit `1f3fc9626ff47eb0b113f442b41bdebfd4b9d2c3`.
Formatting, 76 Rust tests, Clippy with warnings denied, actionlint, and the aggregate `status-check` succeeded.
The live integration test is ignored by ordinary CI and must be run explicitly with credentials.
The existing Approve Request workflow also succeeded, but it ran the legacy default-branch implementation and is not evidence for the new Rust approval flow.

## Live API checks

The public [testing-securefix-server](https://github.com/civitaspo/testing-securefix-server) repository was created for isolated fixtures.
This test added no custom secrets, App keys, production policy capability, or production branch-protection changes.
The test uses an ephemeral authenticated-user token in the local process and writes only to this exact repository.
Its branches and open PRs remain available for inspection; no fixture PR was merged.

The ignored test in [`tests/github_api.rs`](../tests/github_api.rs) passed twice.
The second run strengthened stale-head rejection to require a semantic GraphQL rejection, rather than accepting any request error.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Signed native commit | The shared `createCommitOnBranch` helper accepted GitHub's valid signature, exact parent, and updated ref. | [First fixture commit](https://github.com/civitaspo/testing-securefix-server/commit/bb01e6fdf2676f0f42e376880618c385016fd399) |
| Stale expected head | GitHub rejected the stale `expectedHeadOid`; the branch remained at the first commit. | [Fixture PR2](https://github.com/civitaspo/testing-securefix-server/pull/2), live test assertions |
| Additions and deletions | The next signed commit had the captured parent; the added file's bytes matched and the deleted file returned 404. | [Final fixture commit](https://github.com/civitaspo/testing-securefix-server/commit/9fe2d1a90d09ab70458aedee1ecc9a13ac4de2e3) |
| Stale merge head | REST merge with the earlier SHA returned HTTP 409; PR2 remained open. | [Fixture PR2](https://github.com/civitaspo/testing-securefix-server/pull/2), live test assertions |
| Encoded branch-ref path | The exact `heads%2F...` path used by native Securefix resolved to the expected current head. | [Initial fixture PR1](https://github.com/civitaspo/testing-securefix-server/pull/1), REST ref read-back |

To repeat, set `SECUREFIX_LIVE_TEST_REPOSITORY=civitaspo/testing-securefix-server` and provide `SECUREFIX_LIVE_TEST_TOKEN` through the process environment, then run:

```sh
cargo test --locked --test github_api -- --ignored --nocapture
```

The test refuses any other repository.
It reads the current production main SHA only to exercise the shared API write guard.
It calls the API helper directly; it does not claim that the PR's runtime is the active production revision.

## Deployment checks still required

Full approval, merge, release, settings activation, and Securefix intake/provenance/artifact flows remain unverified against GitHub for the Rust implementation.
Authenticated-user commits do not prove Server App signatures, installation scopes, machine-user review permissions, GPG signing, or immutable release publication.

Production main was `de2c66e03e2c63cdd5dddec0229e948e4f442236` during these checks.
Its `main` environment permits only the `main` branch, and label events execute the default-branch workflow.
It does not yet contain `policy.json`; a pre-deployment call to Rust `securefix validate-event` stopped at that missing policy before processing the event or creating a token.
Running PR code as an active privileged runtime would violate the accepted revision and environment boundaries.
No production ruleset, environment restriction, runtime check, or client pin was changed to enable this probe.

For the full scratch lifecycle, both Client App ID `3872492` and Server App ID `3872533` must be installed for the scratch repository, and its client credentials and exact reviewed capability entry must be configured during staging.
Their installation state was not verified with an App-authenticated token in this run.
Follow the [migration sequence](migration.md) after review and deployment; the API probe does not replace those lifecycle tests or activation attestation.
