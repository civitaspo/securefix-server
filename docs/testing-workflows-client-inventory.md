# Testing client workflow inventory

**Historical inventory before the corrected migration.** Snapshot of the 14 workflows in the previously captured `testing-securefix-server/.github/workflows` directory. This preserves the routes and planned changes at that time. The deployed configuration below supersedes this historical snapshot. The three old testing callers pin pre.1 source while the active test control selects pre.2; their source mismatch is rejected before normal processing. The runtime column records their declared route, not successful execution.

| File / feature | Trigger | Calls | Current runtime | Actual run repository | Planned change |
|---|---|---|---|---|---|
| `testing-approve-request.yml` — approval request | `pull_request_target` opened/synchronize/reopened/ready; owner `/approve` comment | `securefix-server/testing-reusable-approve-request.yml@f0a8090` | Testing pre-release `v0.2.34-pre.1`; qualified against the test control | `civitaspo/testing-securefix-server` | Keep; regenerate the caller pin to the reviewed testing reusable revision. |
| `testing-merge-request.yml` — merge request | Issue comment containing `/merge` from owner or Renovate on its own PR; first attempt | `testing-reusable-merge-request.yml@f0a8090` | Testing pre-release `v0.2.34-pre.1` | `civitaspo/testing-securefix-server` | Keep; regenerate the caller pin to the reviewed testing reusable revision. |
| `testing-policy-check.yml` — policy check | `pull_request_target` opened/synchronize/reopened/ready; push to `main` | `testing-reusable-policy-check.yml@f0a8090` | Testing pre-release `v0.2.34-pre.1` | `civitaspo/testing-securefix-server` | Keep; regenerate the caller pin to the reviewed testing reusable revision. |
| `release-pr.yml` — create/update release PR | Push to `main`; manual dispatch with optional version | `reusable-release-pr.yml@1e2866c` | Production active stable `v0.2.33` | `civitaspo/testing-securefix-server` | Delete; its release-PR function must be provided by the testing caller route. |
| `release-pr-sync.yml` — sync release PR title/body | Manual dispatch | `reusable-release-pr-sync.yml@1e2866c` | Production active stable `v0.2.33` | `civitaspo/testing-securefix-server` | Delete; use the testing release-sync caller. |
| `release-tag.yml` — publish a release tag | Closed merged `release/next` PR; manual retry with PR number | `reusable-release-tag.yml@1e2866c` | Production active stable `v0.2.33` | `civitaspo/testing-securefix-server` | Delete; use the testing release-tag caller. |
| `client-app-smoke.yml` — Client App token probe | Manual dispatch on `main` | Pinned server checkout and Rust `github_api` test binary | Probe binary from server revision `678e10c`; no Securefix runtime | `civitaspo/testing-securefix-server` | Delete; the test caller routes already exercise Client App label creation. |
| `runtime-smoke.yml` — artifact/attestation smoke | Push touching this workflow on `main`; manual dispatch | `actions/attest`, GitHub release CLI operations; no Securefix workflow | Synthetic archive containing only a source SHA | `civitaspo/testing-securefix-server` | Delete; replace no part of the runtime route with this synthetic publication. |
| `verify-server.yml` — candidate server verification | Manual dispatch | `testing-securefix-server.yml@97269f5` | Candidate harness selected by that pinned testing workflow | `civitaspo/testing-securefix-server` | Delete; use the dedicated testing callers and their qualified runtime route. |
| `verify-published-runtime.yml` — verify published CLI/config | Manual dispatch on `main` | `load-cli.yml@7819d4a`, pinned install Action, `csm-actions/securefix-action@1b770a7` | Production active stable `v0.2.33` | `civitaspo/testing-securefix-server` | Delete; it verifies production runtime and does not exercise the testing route. |
| `ci.yml` — ordinary status check | PR opened/synchronize/reopened; push to `main`; manual dispatch | Local no-op `ok` and `status-check` jobs | No Securefix runtime | `civitaspo/testing-securefix-server` | Keep unchanged as unrelated repository CI. |
| `testing-ci.yml` — testing status check | PR opened/synchronize/reopened; push to `main`; manual dispatch | Local no-op `ok` and `status-check` jobs | No Securefix runtime | `civitaspo/testing-securefix-server` | Keep unchanged as the testing check required by the migration fixture. |
| `testing-required-ci-fixture.yml` — required-check fixture | Owner manual dispatch with exact head and selected result; restricted migration branch | Local exact-head assertion and selected status result | No Securefix runtime | `civitaspo/testing-securefix-server` | Keep for the recorded required-CI rejection case. |
| `fixture-validation.yml` — fixture diff check | PR opened/synchronize/reopened | Checkout and `git diff --check` | No Securefix runtime | `civitaspo/testing-securefix-server` | Keep unchanged as fixture CI. |

The three `testing-*` feature callers already target testing reusable workflows, but they are pinned to the earlier `pre.1` revision. The three release callers still invoke the production `v0.2.33` reusable workflows. The next reviewed consumer change should pin all six feature callers to the reviewed testing reusable revision and remove the three production release callers plus the four smoke/verify workflows listed above. The two CI workflows and fixture validation remain in place.


## Historical deployed configuration after PR276 and PR279

Independent readback: `/private/tmp/securefix-phaseb-native-corrected-evidence/final-native-caller-routing.json` and `normal-recovery-independent.json`.
All six feature callers have `testing-` file/display names and pin `civitaspo/securefix-server/.github/workflows/testing-reusable-*.yml@18163e82ad5c6938676ab6cf008e765cd0c7383b`.
Their selected qualified runtime is `v0.2.34-pre.6`; isolated control generation six is `5396753b8b5e8e9efe15acf191da8ebc47aac9fad0ec728fed43567fbc2e05aa`.
The independent protected-main host is `a18a496fce397bfde57a0f901107e1d634e4d36f`.
Workflow-file location does not imply the reusable job runs in the server repository.

| Caller / trigger | Testing reusable suffix | Actual CLI execution repository and shared production commands | Actual evidence |
|---|---|---|---|
| `testing-approve-request.yml`: PR target events; owner `/approve` | `approve-request` | Caller captures/dispatches in testing-securefix-server; server runs normal approve validate/apply with existing User bot PAT | Caller39244411457 → server39244474088; exact-head User review5570826725; fresh PR279 User review5570915919 |
| `testing-merge-request.yml`: eligible `/merge` comment | `merge-request` | Caller captures/dispatches; server runs normal merge authorize/wait/apply | Caller39245747840 → server39245820011; PR279 merged |
| `testing-policy-check.yml`: PR target events; main push | `policy-check` | Caller runs check capture/dispatch; server runs check locate/validate/apply | Callers39244409105/39245400753 and server39245608824 passed; source/control recorded in process log |
| `testing-release-pr.yml`: main push; optional explicit-version dispatch | `release-pr` | Caller runs release prepare and native client preparation/dispatch; server performs the shared CSM signed write/PR flow | Caller39244432886 → server39244505228 → PR278, v0.1.0-pre.4 |
| `testing-release-pr-sync.yml`: manual dispatch | `release-pr-sync` | Caller runs normal release sync-pr with the same GITHUB_TOKEN permission as production | Run39244710083 passed |
| `testing-release-tag.yml`: merged release/testing-next PR; explicit PR retry | `release-tag` | Caller resolves/builds/tags and requests release; server signs/publishes | Run39245879033 tag/build passed; request-server rejected before label; minimal shared-code fix and new qualified runtime pending |

The final directory contains exactly ten workflows: these six callers and the four existing CI/fixture workflows retained for the reasons in the historical inventory.
PR279 removed the three production release callers and four obsolete smoke/verify workflows; no unprefixed production Securefix caller remains.
No server-wide execution centralization, split-review command, additional auth platform, dedicated App, secret relocation, or extra Environment approval is used.

## Current deployed configuration — Phase B complete

This section supersedes the historical inventories above. Exactly ten workflow files remain: six feature callers below, plus unchanged `ci.yml`, `testing-ci.yml`, `fixture-validation.yml` and the bounded refusal fixture `testing-required-ci-fixture.yml`.
All six caller file/display names start with `testing-` and reference `civitaspo/securefix-server/.github/workflows/testing-reusable-*.yml@c1195a11ddf07e324f3fc81aadbb55a6935f0d94`.
All actual feature executions below selected qualified immutable `v0.2.34-pre.9` and isolated control7 (`0165196de8c2d3bb6221275eb6cf1f2673792a6b9d6a12ce3ab4c89f0a35f5e0`). Independent qualification host `fcf36237c8ea2d331f5c2d8e24d3cc41fe495030` includes the host-only directory/metadata corrections.

| Caller / trigger | Testing reusable suffix | Actual execution repository and shared normal processing | Successful source9 evidence |
|---|---|---|---|
| `testing-approve-request.yml`: PR target events, owner `/approve` | `approve-request` | Caller captures/dispatches in testing-securefix-server; server runs approve validate/apply with existing User bot PAT | Caller39250588840 → server39250675449 → exact-head civitaspo-bot User review5571392727 |
| `testing-merge-request.yml`: eligible `/merge` comment | `merge-request` | Caller captures/dispatches; server runs merge authorize/wait/apply | Caller39250834291 → server39250919292 → PR289 merged |
| `testing-policy-check.yml`: PR target events, main push | `policy-check` | Caller captures/dispatches; server runs check locate/validate/apply | Native server39252589546; source9/control7 process log |
| `testing-release-pr.yml`: main push, optional version dispatch | `release-pr` | Caller release prepare/native client dispatch; server shared CSM signed commit and PR | Caller39252099978 → server39252200081 → signed PR290, v0.1.0-pre.5 |
| `testing-release-pr-sync.yml`: manual dispatch | `release-pr-sync` | Caller runs normal release sync-pr with the same GITHUB_TOKEN permissions as production | Caller39252447574 passed |
| `testing-release-tag.yml`: merged release/testing-next PR, explicit PR retry | `release-tag` | Caller resolves/builds/tags/requests; original Client App creates server label; server preflights/signs/publishes | Caller39253227847 → server39253690614 → immutable v0.1.0-pre.5, release417276895 |

The reusable files live in securefix-server; caller jobs actually run in testing-securefix-server. Server event workflows actually run in securefix-server. No server-wide execution move or split-review CLI remains.
Production stable v0.2.33/control and settings were not changed. Shared Apps, existing Client secret, User reviewer and original Client App label transport remain; operations/tokens target the required test repositories/permissions. The three temporarily suspended notifications are active.

Independent final routing/content-identity and workflow/control readback: `/private/tmp/securefix-phaseb-native-corrected-evidence/phaseb-final-caller-routing.json` and `phaseb-final-independent-readback.json`. Overall evidence index: `phaseb-completion.json`. Current same-source two-run CLI reuse proof: `host10-multi-run-build-reuse.json`; prepare and sync reuse exact artifact12185653021 without recompilation, while revalidating current runtime/control/authority.
