# Workflow lockfile rollout evidence, 2026-10-20

This is an in-progress evidence record. Unverified rows are not deployment claims.

The configured settings set contains nine repositories. `testing-securefix-server` is the separate scratch repository. The complete pre-change workflow paths and `uses` references are in [the inventory](workflow-lockfile-inventory-2026-10-20.json).

| Repository | Captured default head | Workflow count | Initial lockfile | Migration PR | Result and remaining work |
| --- | --- | ---: | --- | --- | --- |
| civitaspo/dotfiles | `cff4d812b44cd69e6904e1b45ba2f45c21093135` | 4 | Absent | Pending | Caller migration and request verification pending. |
| civitaspo/securefix-server | `2f56c5f75b74c588715995a58eff86017388b286` | 42 | Absent | [#133](https://github.com/civitaspo/securefix-server/pull/133) | Merged at `f268f25a2237ba3b76f3a0b5b4a8baa9e1d218ed`; build-helper correction required before publication. |
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
The authenticated policy form exposes the Preview rule type `require_lockfile` with no parameter fields.
A disabled, scratch-only POST using that type and an empty parameter object was rejected with HTTP 422 (`Invalid property /rules/0: data matches no possible input`) under API version `2022-11-28`.
No policy was created and no enforcement setting has been changed. UI support alone does not establish REST support.
The existing herdr-linear-agent policy `7889` is active, named `Require workflow lockfiles`, and returned `rules: [{"type":"require_lockfile"}]` without parameters. Its workflow condition includes `~ALL`.
A second disabled scratch probe with those rule bytes was rejected under both `2022-11-28` and `2026-03-10`; the scratch policy list remained empty. New enforcement is deferred by the owner until the write API supports this rule. See [the maintenance contract](workflow-lockfiles.md#enforce-through-repository-settings).

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

## Reviewed candidate rehearsal

Source `32a3beb3da9108aa3941352ca46b85b7a7baec57` passed [CI 39348364991](https://github.com/civitaspo/securefix-server/actions/runs/39348364991), including the official Linux tool installation and frozen lockfile verification.
The normal Client App request and server approval route produced exact-head bot review `5579419816` through [approval run 39348437306](https://github.com/civitaspo/securefix-server/actions/runs/39348437306).
This is the server source PR's approval, not evidence for herdr-linear-agent #166.

Its direct scratch [prepare 39348433270](https://github.com/civitaspo/securefix-server/actions/runs/39348433270) and [verify 39348845493](https://github.com/civitaspo/securefix-server/actions/runs/39348845493) both succeeded using the exact candidate artifact and fixture state.
The positive fixture [#291](https://github.com/civitaspo/testing-securefix-server/pull/291) merged at `b18cf19382e98331b3954ce262e9da9bb7f61f0d`.
The stale fixture was #292 and the rendered distribution fixture was #293.
The distribution fixture's real autofix caller, `status-check` and `scratch-push-status-check` succeeded.
The control probe verified expected-head conflict rejection and stale identity rejection after ABA; it explicitly does not certify production publication, activation or distribution.

This rehearsal preceded the additional direct-harness fixture lockfile maintenance change.
The final protected-main source must be qualified separately before runtime promotion.
No production control or consumer pin was changed by this rehearsal.

## Source-bound local action correction

The first protected-main [prepare 39349484429](https://github.com/civitaspo/securefix-server/actions/runs/39349484429) and [testing publisher 39349488015](https://github.com/civitaspo/securefix-server/actions/runs/39349488015) failed in `setup-cli`, before candidate execution or release publication.
The supported `$/` reference downloads the action under `_actions`; the helper incorrectly derived the Git checkout from `github.action_path`.
Its reuse script therefore reported `fatal: not a git repository`.
No identical retry was dispatched. The fix binds build and artifact reuse to `github.workspace` while continuing to load the helper script from its defining action path.

The correction was merged at `2ed0aecd893b8116e15c46b84e01bcece8020f18` through [PR #134](https://github.com/civitaspo/securefix-server/pull/134).
Exact head `6685f5547a95956b79a294587f3885906646f1b1` passed [CI 39350166044](https://github.com/civitaspo/securefix-server/actions/runs/39350166044), including the downloaded-action build and reuse regression.
The initial correction head failed the required package-version gate; its successor advances the package to `0.2.34-pre.16`. No version gate was bypassed.


## Post-correction exact-source qualification

Protected-main source `2ed0aecd893b8116e15c46b84e01bcece8020f18` passed direct scratch [prepare 39350717556](https://github.com/civitaspo/securefix-server/actions/runs/39350717556) and [verify 39351358722](https://github.com/civitaspo/securefix-server/actions/runs/39351358722).
The positive fixture #294 merged at `986e9b2d04378baf2fd416522d866bf584ef4bc0`; stale fixture #295 was rejected after its head changed, and distribution fixture #296 was checked and closed.
These are direct-harness results, not proof of the published native caller-to-server mutation route.

Main [CI 39350671991](https://github.com/civitaspo/securefix-server/actions/runs/39350671991) passed on attempt 2.
Attempt 1 passed lock verification, tests, Clippy and CLI build, but ArtifactService `CreateArtifact` timed out five times.
The first testing publisher [39350836935](https://github.com/civitaspo/securefix-server/actions/runs/39350836935) correctly rejected the source while required CI was pending.
Only after CI succeeded was a fresh [publisher 39351800495](https://github.com/civitaspo/securefix-server/actions/runs/39351800495) dispatched; it succeeded.

The immutable testing release `v0.2.34-pre.16` has release ID `417902204`, asset ID `657898718`, archive SHA-256 `fcb04785c0540f9ee14c98a63d1b6dcbb9b7082274204604c914972673a30391`, and source `2ed0aecd893b8116e15c46b84e01bcece8020f18`.
Publication alone did not activate it.
[Control fixture PR #297](https://github.com/civitaspo/testing-securefix-server/pull/297) activated generation 8 through the dedicated [merge run 39352397120](https://github.com/civitaspo/securefix-server/actions/runs/39352397120).
Its merged scratch main is `0a5f7bc7ab8be436be07a5622069a9942b7ea7c3`, and the active control identity is `7ad14a108d8a811de1579dcfc8c3fc82b75cca3a98c1b1efa88d012cb2f9b65d`.
Caller migration and native approval evidence follow separately; activation alone does not certify either.

The owner confirmed the existing herdr policy was created through the UI after its PUT was rejected with the same 422.
The owner explicitly deferred new native enforcement until API write support is available.
No additional policies or mandatory repository-settings audit are deployed by this rollout.

The subsequent initial-deployment proposal [39352651310](https://github.com/civitaspo/securefix-server/actions/runs/39352651310) rejected the initialized scratch repository because the legacy managed caller wrappers were absent (`required managed caller workflow is missing`).
No identical retry or legacy-wrapper restoration was performed; the existing testing runtime distribution route is used for this update.

The existing [testing distribution 39352892134](https://github.com/civitaspo/securefix-server/actions/runs/39352892134) succeeded and opened [caller migration PR #298](https://github.com/civitaspo/testing-securefix-server/pull/298) at `36c5184bcbcf1b7a91cbb898460810a8dad1528a`.
This certifies proposal generation, not caller deployment or native approval.

PR #298's pre-migration `pull_request_target` [policy run 39353126806](https://github.com/civitaspo/testing-securefix-server/actions/runs/39353126806) and [approve run 39353127247](https://github.com/civitaspo/testing-securefix-server/actions/runs/39353127247) rejected `testing caller workflow source differs from active test control`.
Run provenance identified base `0a5f7bc7ab8be436be07a5622069a9942b7ea7c3` and the obsolete base caller/reusable source `c1195a11ddf07e324f3fc81aadbb55a6935f0d94`, rather than the migrated PR files.
The two required `status-check` contexts passed. The obsolete callers were not retried; the reviewed caller-migration lane retains its own exact-file, review, command, policy-check and required-CI validation.

The dedicated [testing caller migration 39353436203](https://github.com/civitaspo/securefix-server/actions/runs/39353436203) succeeded, including authorization, required-CI readiness and exact-head merge.
PR #298 merged at `5d1cdf79c52a2d83b9c9013c87e94632f17ddc05`; all six testing callers now select `2ed0aecd893b8116e15c46b84e01bcece8020f18`.
The deployed lockfile blob is `7573196b0f05caf6f4f5f01c6262f66ae8851f7a`. This deployment result is separate from the native approval test.

The native owner fixture [PR #300](https://github.com/civitaspo/testing-securefix-server/pull/300) preserves workflows and lockfile, with signed head `72eefbd8285bd1a6e6377d9b4c06e6eb2b32c78f` parented to `5d1cdf79c52a2d83b9c9013c87e94632f17ddc05`.
Its [CI 39354053084](https://github.com/civitaspo/testing-securefix-server/actions/runs/39354053084) passed. Owner `/approve` comment `6281243163` triggered native [request 39354147907](https://github.com/civitaspo/testing-securefix-server/actions/runs/39354147907), which succeeded through capture and Client App dispatch, producing the server label event.
The subsequent testing server approval result is recorded separately; request success alone does not establish review creation.

Native [server approval 39354216345](https://github.com/civitaspo/securefix-server/actions/runs/39354216345) succeeded through current-commit validation, approval creation and one-time label cleanup.
PR #300 received `civitaspo-bot` APPROVED review `5579788813` on exact head `72eefbd8285bd1a6e6377d9b4c06e6eb2b32c78f`, bound to control `7ad14a108d8a811de1579dcfc8c3fc82b75cca3a98c1b1efa88d012cb2f9b65d`.
Its [policy check 39354129957](https://github.com/civitaspo/securefix-server/actions/runs/39354129957) and required CI passed. The fixture remains unmerged.
This is actual Client App → server label → Bot approval evidence, rather than direct-harness shared-core approval.

## Stable runtime source

[PR #135](https://github.com/civitaspo/securefix-server/pull/135) merged through normal [server merge 39354511418](https://github.com/civitaspo/securefix-server/actions/runs/39354511418) at signed source `4b2a64399c72e1dbed7deee10ee2867d59f24805` (`v0.2.34`).
This source excludes the integration repository from the production caller matrix while retaining it in dedicated testing flows.
The merge itself did not change production active control. Exact-source CI and candidate qualification are tracked independently from the earlier pre.16 native test.

Stable source passed [CI 39354638017](https://github.com/civitaspo/securefix-server/actions/runs/39354638017) and [prepare 39354661216](https://github.com/civitaspo/securefix-server/actions/runs/39354661216).
[Production publisher 39354944426](https://github.com/civitaspo/securefix-server/actions/runs/39354944426) succeeded after CI was green.
The immutable, non-prerelease `v0.2.34` has release ID `417917770`, asset ID `657963947`, source `4b2a64399c72e1dbed7deee10ee2867d59f24805`, and archive SHA-256 `65bf759e1eed78da0db7868235d6b2c80622e006ae21c7b6d765b0f3d3e579b9` (4,257,842 bytes).
Publication did not activate this source.

The first stable [verify 39355240722](https://github.com/civitaspo/securefix-server/actions/runs/39355240722) failed after its required stale-fixture owner command was initially missing.
While it waited, the now-working native server merge [39355105285](https://github.com/civitaspo/securefix-server/actions/runs/39355105285) merged positive fixture #301 at `7c9ed528175410420966adc454def28012ef6527`.
Once the missing stale command arrived, direct verification correctly rejected `pull request is not open at the authorized head` and cleaned its fixtures.
This was a fixture orchestration race, not a lockfile startup failure; no production activation followed. A fresh prepare is required, with all three owner command inputs supplied before immediate verify dispatch.

The fresh [prepare 39355951913](https://github.com/civitaspo/securefix-server/actions/runs/39355951913) succeeded, followed by [verify 39356116130](https://github.com/civitaspo/securefix-server/actions/runs/39356116130) with all three command inputs present.
This verify rejected `positive policy check was published before the native auto-merge probe`.
The working native testing flow had already published a check for the active testing control, whereas the direct probe expected no policy check of any control. This exposed a direct-harness assumption rather than a production authorization failure.
No further unchanged-source verification was dispatched. The proposed correction scopes readiness probes to the exact head and full control identity under test, preserving rejection before that control publishes its policy result.
The published v0.2.34 remains immutable and unactivated; the corrected candidate advances to v0.2.35.

## Revised direct verification contract

[PR #136](https://github.com/civitaspo/securefix-server/pull/136) passed exact-head [CI 39356796270](https://github.com/civitaspo/securefix-server/actions/runs/39356796270) and Bot review `5579944778` at `8063f1aaf797e94d4e01eb278c70e8687a1e0dd7`, under production control `3006b3f1706a226100c567b3aca38377efaeb0dfdf0b93c3a7bdd55c6ff995d1`.
It merged through normal [server merge 39357076865](https://github.com/civitaspo/securefix-server/actions/runs/39357076865) at signed source `ad5be9abffef306c0e80e551b7dca659b389c55c` (`v0.2.35`).
Local full tests passed (42 library, 297 CLI passed with 2 ignored, 22 bootstrap, 2 native-client, 1 testing-runtime), along with fmt, Clippy, pinned actionlint, official generation and frozen verification.
The corrected harness requires the policy result for the exact head and structural control under test, rejects duplicate matches and proves that another control does not grant readiness. Fixture lock generation and exact path/status checks use the immutable recorded base. Production authorization logic is unchanged.

Exact v0.2.35 source passed [CI 39357216476](https://github.com/civitaspo/securefix-server/actions/runs/39357216476) and [prepare 39357249535](https://github.com/civitaspo/securefix-server/actions/runs/39357249535), including official fixture lock generation.
[Verify 39357599476](https://github.com/civitaspo/securefix-server/actions/runs/39357599476) validated fixture files and completed the positive merge before rejecting `stale-head fixture unexpectedly has current review or policy check before its probe`.
The stale fixture had a native approval for active scratch control `7ad14a108d8a811de1579dcfc8c3fc82b75cca3a98c1b1efa88d012cb2f9b65d`, which the generic review probe counted toward the candidate structural control.
Only duplicate native testing merge runs 39357661993 and 39357671106, mapped to the two direct-test fixtures and owner commands, were canceled to keep the direct merge probe isolated. Native approval remained enabled and exposed the review-scope defect.
The correction uses the existing exact reviewer, head and control approval validator for all three direct readiness probes. Production authorization is unchanged. No unchanged-source retry was made, v0.2.35 was not published, and the corrected source advances to v0.2.36.
