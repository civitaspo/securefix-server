# Control successor verification, 2026-10-17

## Activated generation one

The approved bootstrap scratch run [39034639333](https://github.com/civitaspo/securefix-server/actions/runs/39034639333) passed before initial publication. Fixed-host proposal run [39034975925](https://github.com/civitaspo/securefix-server/actions/runs/39034975925) published immutable `v0.2.23`, opened descriptor PR [#100](https://github.com/civitaspo/securefix-server/pull/100), and left activation for a separate dispatch. Its exact head passed required CI and received the owner's review. Separate merge run [39035472064](https://github.com/civitaspo/securefix-server/actions/runs/39035472064) passed.

The resulting signed protected-main commit is `892e0749dba537a4e06e75a143236c1be282d65b`. It changes only `control/active.json` from parent `f05a400115ef744070671028865a6269d65bae8b`.

| Descriptor binding | Value |
| --- | --- |
| Generation | `1` |
| Runtime source | `f05a400115ef744070671028865a6269d65bae8b` |
| Full control identity | `a2f59b941ae1a92bd07513e672f64ed6ff9301fc48e254047d91874784b838ef` |
| Release ID | `415808229` |
| Archive asset ID | `650489932` |
| Archive SHA-256 | `258fbab974214a0af9f1e349b20d1d4f319ac47c78ea35171ca516013e4043c2` |

## Published loader and test-validator failure

Run [39036197122](https://github.com/civitaspo/securefix-server/actions/runs/39036197122) used the active descriptor from the new main. Its `trusted-runtime-main / load` job passed the actual source-bound attested published-runtime loader. Its credential-free candidate build and tests passed.

Both `scratch` and `client-smoke` failed their defining-workflow validation with `canonical runtime tag does not directly target the default branch source`. Every App-token creation step in those jobs was skipped. The test helper incorrectly required the published source to equal current main, although descriptor activation necessarily advances main beyond the runtime source. This is a test-validator failure; the overall scratch run did not pass.

## Successor changes and remaining verification

The correction selects the tested published runtime from the active descriptor and checks its immutable release ID, asset ID and archive digest. A credential-free test validator is built from captured signed current main and rejects any later main change. The candidate remains isolated with scratch-only credentials.

Distribution proposes canonical caller PRs without merging them. The dedicated owner-dispatched migration lane requires an exact-head control-bound owner review after activation, separate fresh unedited owner commands, canonical signed generated files, current base, required CI and the Server App policy check. It repeats validation before expected-head merge and verifies resulting default-branch file bytes.

Local checks passed with Rust 1.99.0: formatting, 301 tests (32 library, 246 CLI, 21 bootstrap and 2 native-client), Clippy with warnings denied, pinned actionlint and diff checks. Two existing tests remain ignored. The composed API fixture accepts the canonical migration with its owner review, commands and active control, and rejects changed head/control plans. The shared merge fixture confirms that the final authorization callback can prevent the API write. A separate same-model code review found no actionable security or correctness defect.

These successor changes are not yet deployed. A reviewed source PR, scratch prepare/verify, normal publication, generation-two activation and caller migration completion remain required. The full new migration workflow has not been exercised in production. The complete workflow must first succeed on the configured scratch caller after activation; shared-helper and fixture results do not alone certify that dispatch context.
