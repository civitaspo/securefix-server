# Workflow lockfile rollout evidence, 2026-10-20

This is an in-progress evidence record. Unverified rows are not deployment claims.

The configured settings set contains nine repositories. `testing-securefix-server` is the separate scratch repository. The complete pre-change workflow paths and `uses` references are in [the inventory](workflow-lockfile-inventory-2026-10-20.json).

| Repository | Captured default head | Workflow count | Initial lockfile | Migration PR | Result and remaining work |
| --- | --- | ---: | --- | --- | --- |
| civitaspo/dotfiles | `cff4d812b44cd69e6904e1b45ba2f45c21093135` | 4 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/securefix-server | `2f56c5f75b74c588715995a58eff86017388b286` | 42 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/dbt-authorized-models | `9ee99e05e125870f9704dbf339f18ec9c6e4c0df` | 15 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/dbt-snowflake-iceberg-sync | `38f79189a10936ee6d5e9ddcd9638f931f134b08` | 15 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/dbt-snowflake-rap-enforcement | `71b0bbc42e2ab22faa9d8518c032e0171127ad68` | 15 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/terraform-provider-sigma | `8e8e1013a7a45c27280281b6dc1b7befef691273` | 15 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/herdr-linear-agent | `8ab60297001e8dec9cf4c5e24cd0f6ca783da3de` | 15 | Present | Pending | Caller migration and request verification pending. |
| civitaspo/hook-relay-client-rs | `2b3289bb2e9026745e54b83055ff9305b6b7da74` | 15 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/herdr-infobox | `2316f8f3e213d68bc5dff456b550532f87b26c71` | 14 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/testing-securefix-server | `c47ddd187a9e016f634e921910e05d920118ddb5` | 10 | Absent | Pending | Caller migration and request verification pending. |

## Verified scratch pilot

The owner-authored, GitHub-signed branch `experiment/actions-lockfile-pilot` contains a three-level reusable workflow and an official-tool-generated lockfile.
Source `9a71a8c7c60c919ba8fbaaf4e7fa05193ac76125` completed [run 39347236655](https://github.com/civitaspo/testing-securefix-server/actions/runs/39347236655) successfully.
The job `nested / nested / verify` ran checkout at `3d3c42e5aac5ba805825da76410c181273ba90b1` and completed its leaf command.
This proves nested startup and leaf execution. It does not prove Client App request delivery or Securefix approval.

The first workflow_dispatch attempt returned 404 because the new workflow was absent from default main.
The pilot then used a branch-scoped push trigger. This was a trigger-discovery issue, not a lockfile startup retry.

## Original failure and source requirements

[herdr-linear-agent run 39216144827](https://github.com/civitaspo/herdr-linear-agent/actions/runs/39216144827) has conclusion `startup_failure`, no job check runs, and head `a3199aa02d0ec4764d80b9da0ca7af937b9e8e28`.
At capture time this is also the latest head of [PR #166](https://github.com/civitaspo/herdr-linear-agent/pull/166).
The pinned production server revision `1e2866cbab65c5ef4e218fa6853300c2731e73c0` has no workflow lockfile.
Neither the testing caller revision `c1195a11ddf07e324f3fc81aadbb55a6935f0d94` nor the old testing loader revision `9ec4043ce71f454811ef676b82dcba1314a5f0bb` has one.
Those historical commits cannot be repaired. Their callers must select a qualified lockfile-bearing revision.

## Repository-settings enforcement

The server and scratch repository each returned an empty repository Actions policy list.
The official REST schema does not document a Require lockfile rule.
No enforcement setting has been changed. See [the maintenance contract](workflow-lockfiles.md#enforce-through-repository-settings).

## Local generation checks

The official v0.2.0 tool generated lockfiles in disposable immutable-source snapshots for all eight settings-managed client repositories.
Each subsequent frozen `--verify --json` completed with exit 0 and `valid: true`.
These are local generation/format checks, not deployed caller changes or validation of the historical server source pins.
The server's generated lockfile covers all 42 workflows and also passed frozen verification.
Workflow structure tests and the pinned CI actionlint command passed locally.

Independent comment review found no added explanatory code comments requiring removal.

`cargo test --locked` passed locally (42 library, 296 CLI, 22 bootstrap, 2 native-client, and 1 testing-runtime tests).
`cargo fmt --all -- --check` passed.
`cargo clippy --locked --all-targets -- -D warnings` passed.
