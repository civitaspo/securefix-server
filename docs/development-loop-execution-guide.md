# Execution guide for immutable Securefix deployments

Use with the [refactoring plan](development-loop-refactoring-plan.md). This guide makes investigation and implementation bounded enough for Luna execution; it does not authorize guessing unresolved trust design. Keep Rust, one repository and the existing `testing-securefix-server` scratch repository. No production behavior changes merely because these documents exist.

## Rules for every unit

1. Read repository instructions and the affected current contracts. Capture `git status --short`, `git rev-parse HEAD` and existing changes; do not overwrite unrelated work.
2. Work in small coherent slices. Do not require a separate PR, handoff or ADR for every tiny scratch probe; implement, test and fix the same affected slice when practical. Record assumptions as facts, agreed targets or open decisions. Settle only the contracts that the affected route needs; do not compensate for a failed gate by weakening a validator.
3. Before touching an operational workflow/local dependency, compare it with the captured live dependency closure. Keep the existing deployment functional with the active runtime. Prefer new, non-operational implementation paths plus explicit scratch entrypoints until cutover.
4. Reuse Rust API, provenance, expected-head, archive, signature, canonical workflow, lockfile and integration helpers. Inspect `src/lib.rs` before sharing binary-only code; move only the necessary helper into a suitable existing library module. Avoid a broad workspace/module rewrite.
5. Run focused relevant tests, then standard checks once after assembling a behavioral change. Preserve the pinned toolchain, action SHA/version comments and CI's actionlint exceptions. Use the actionlint command from `.github/workflows/ci.yml`, not a guessed command or downloaded unpinned tool.
6. For hosted behavioral evidence, use direct immutable candidate artifacts first. Read `docs/testing.md` and `docs/integration-testing.md`; use actual supported inputs and prepare/verify fixture artifacts. Never assume proposed scenario names already exist. No production credential in candidate execution; direct owner-selected scratch probes use one source-bound CLI under the documented threat model, not an invented second validator/container boundary.
7. Preserve failed runs and inspect the cause before retrying. Fixture/PR creation and passing unrelated checks are not successful feature evidence. The owner authorizes disposable direct edits to the scratch repository's workflows/configuration, PRs/branches and repository settings, including delete/recreate cycles. Preserve evidence first, verify repository and object identity, and clean up captured scratch state when useful; this authorization does not include production state or shared credentials/App permissions.
8. At completion report changed files/contracts, checks, evidence and unresolved conditions. Planning, code inspection and a local test do not certify deployment. GitHub PR text/comments must be English. The existing owner authorization for scratch edits/settings does not need to be reconfirmed; do not touch production or post owner commands outside their existing authorization.

Standard implementation checks, after focused tests:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Documentation-only work needs local links, source accuracy and required CI; do not rerun unchanged live scenarios or Rust suites solely for a plan edit.

## Decision register: settle each contract before its dependent work

Create a numbered ADR after checking `docs/adr/` for the next unused number when a durable design decision needs one; do not create an ADR for each small scratch probe. Record the decision, relevant proof-acquisition algorithm, bounds/failure behavior, and positive/rejection evidence. Track each decision as `open`, `design accepted`, `implemented`, or `scratch qualified`. The first functional probe needs only the contracts it exercises: candidate source/artifact binding, the selected request protocol, required config fields, actor/repository/capability identity, exact PR head, current-write authorization where applicable, and test-only scopes. Complete the broader U02 map and remaining D gates before their dependent units and cutover; they do not block this probe. Publication/cutover compatibility remains unqualified until U08 produces the specified hosted evidence. Stop only the dependent work and report evidence when its contract cannot be proved.

| ID | Investigate | Confirm by | Decision/stop rule |
| --- | --- | --- | --- |
| D01 release binding | Publisher workflow, loader, `src/runtime_archive.rs`, Cargo version and GitHub release/attestation APIs | For the first slice, bind the direct candidate to its exact source SHA, successful scratch producer run/attempt, immutable artifact ID/digest and test repository. Separately trace the generic published path from defining reusable revision through source, tag, immutable release, producer and asset digest. | The first source-bound scratch artifact can be used under the owner-selected development threat model once its exact run/artifact binding is checked. Caller-source and full producer/release proof remain blockers for generic published execution and Client acceptance. PR-target `run.head_sha` can be the PR head while references identify base/main; `pull_requests` can be empty, and `referenced_workflows` can list a skipped call. Do not substitute caller SHA or self-report. Initially support reusable workflows and nested source-owned composites only; standalone remote composites remain unsupported. |
| D02 config schema | `src/config.rs`, `src/policy.rs`, `policy.json`, `.github/testing-policy.json`, embedded Renovate policy, workflow hardcodes, `repo-settings/` | For the first slice, specify the required fields and policy behavior it exercises under the existing strict parser; later map every field and compare equivalent old/new policy decisions | Use a valid explicit fixture with the existing parser. Do not add a second parser, reduced schema or defaults for the first probe. Freeze the complete field map and loading API before broad U04/U05 completion, not before the first probe. |
| D03 authority identity | `src/api.rs`, control/command/request/review markers, workflow locks, configured `[workflow_roles]`, and source-owned ordinary-writer CI inventory | For the first slice, bind its request and any write to exact PR head plus the relevant config/deployment identity and recheck current state at the write. Before cutover, specify canonical role/path encoding and reject an unclassified known ordinary writer. | The first slice proves only its affected route. The required-CI inventory remains a closed check of known ordinary token/write patterns, not an audit of every repository credential. Repo-settings and publisher lifecycles remain separate. |
| D04 anti-replay epoch | Protected-main history access and current replay markers | Edit/revert, merge, rename/delete, path-set changes, unrelated long history, incomplete/shallow graph, byte/time caps and final-head recheck | Proposed ADR 0012 uses a complete blob-filtered, no-depth graph at exact `M` and one first-parent raw path traversal; no commit-count cap. Provisional object-store/time/output bounds and hosted behavior remain unqualified. Never accept current-bytes-only identity or add a mirrored generation/version setting. |
| D05 multi-workflow coherence | Configured ordinary Server role wrappers and first-party reusable/package references | For the first slice, inspect only the selected Client/Server pins and wrapper paths. Before broad rollout, enumerate every role→instance path→literal pin and independently resolved package identity. | A first scratch route does not require all roles or one coherent published release set. Before deployment, initial canonical wrappers must have no local action/workflow/script dependency; group Renovate PRs and reject partial updates; do not infer compatibility from SemVer alone. |
| D06 Client proof/protocol | `src/request.rs`, `src/workflow.rs`, policy/release/intake validators and manifest producers | Trace the selected request's actual wrapper, direct candidate artifact and head binding; later qualify release provenance and all supported protocol fields | Define and test only the selected route's request contract for the first probe. Complete generic source/release provenance for published clients before broad acceptance. Old commands may reject at cutover; do not translate stale legacy authority or require permanent legacy-protocol support. |
| D07 generic publisher and transition authority | `publish-runtime.yml`, `src/control_commands.rs`, `src/control.rs`, bootstrap authority | Qualify the policy-free generic archive/publisher in scratch; establish the exact authorized, head-fenced route for the coherent Server/TOML successor | Do not assume the existing publisher handles the generic archive. A bounded publication adapter or migration executor needs separate justification/review; no runtime bridge is required solely for old Client continuity. Never revive bootstrap/repair or introduce a general bypass |
| D08 reconcile semantics | `src/distribution/`, `src/settings.rs`, templates, repo-settings workflow and Renovate configs | After the first direct scratch proof, encode its persistent workflow/config/settings state in desired state and repeat reconcile to zero diff; later exercise pin repair and update behavior | Direct scratch wiring and scratch repository settings may be used for the first probe without waiting on repo-settings. Final managed state remains owned by repo-settings. Preserve verified compatible pins, reject unsupported structure/protocol, and keep reviewed PRs separate from administrator settings credentials. No auto-merge or downgrade. |
| D09 cutover/self-update/return | Merge API fences, sensitive workflow/config policy, actual known-good release and new Client | Rehearse self-PR, terminal merge, old-command rejection, fresh run and any known-good return path before cutover | A declared downtime window is allowed. The first scratch probe needs only its own current-head/current-authority checks; cutover still requires exact transition authority and fencing. State when a return path is unavailable; no recovery guarantee without rehearsal |

### Current decision status (2026-10-21)

These statuses track current design and implementation evidence. Local review and tests do not certify hosted behavior or deployment. No D gate is complete, and no production switch is ready.

| Gate | Status | Remaining proof |
| --- | --- | --- |
| D01 | Scratch-qualified for the single U05a `workflow_dispatch` path; open for generic published execution and other event types | The 2026-10-21 scratch proof verified a source-pinned reusable producer attestation, local bundle, and exact candidate run/artifact binding for one policy-check request. Earlier event traces still block treating run references or self-reported caller SHA as proof: PR-target runs had `pull_requests=[]`, and an issue-comment run listed a skipped reusable. The mechanism is qualified only for the captured scratch route; generic published Client acceptance and `pull_request_target`/`issue_comment` production wrappers remain open. See the evidence below and [ADR 0013](adr/0013-native-request-producer-proof.md). |
| D02 | Partial disconnected parser; workflow-role syntax and fixture evidence only | The parser has independent consistency review and 17 focused tests, including a separate legacy-policy parity fixture. The required closed `[workflow_roles]` map now derives required operation roles from repository capabilities and validates path syntax and case-insensitive duplicates. Complete the strict schema, settle the authenticated protected-main snapshot reader/loading API, and prove operationally equivalent policy decisions. The parser does not authenticate files, source, pins, or deployment identity. Hosted qualification remains open. |
| D03 | Open | Review the strict ordinary-role map, canonical thin-wrapper validator, closed required-CI inventory of known ordinary writers, package proof in W, and fresh identity check at each in-scope write. Do not claim a universal repository credential audit. |
| D04 | Open | ADR 0012 proposes full blob-filtered history from exact `M` plus one first-parent raw path traversal, without a commit-count cap. Prove parity, shallow/incomplete rejection, provisional byte/time/output bounds, final-head recheck and hosted cost/availability. |
| D05 | Partial inventory only | Qualify coherent pins and package identities across required canonical Server role wrappers; initial W has no local dependency closure. |
| D06 | Partial inspection only | Existing Client fields are traced; new protocol and publisher/source/asset proof remain unqualified. Old protocol acceptance is not a cutover requirement. |
| D07 | Open | Qualify the generic policy-free publisher and exact authorized cutover route. Any bounded publication adapter or migration executor must be independently justified; no old-Client runtime bridge is assumed. Retired bootstrap/repair are not fallback authorities. |
| D08 | Partial read-only contract | Implement and scratch-test the planner; bounded release enumeration and interface proof remain open for highest-SemVer target selection. |
| D09 | Open | Rehearse the exact head-fenced cutover, self-update terminal merge, old-command rejection, fresh new-authority run and any available conditional return path. |

The first hosted functional probe may proceed before the U02 map and U03–U07
delivery units are complete, but only for one bounded route and after its
affected source/artifact, identity, configuration, protocol, head and write
fences are explicit. It does not close D01 generic publication proof, the full
D02 schema, the D03 writer inventory, or any cutover gate.

The U03a local release-resolution checkpoint (2026-10-21) is recorded in
[ADR 0011](adr/0011-generic-release-resolution.md). `package::resolve_release`
accepts a trusted full-SHA implementation pin and resolves the publisher
repository identity, `Cargo.toml` version at that SHA, matching `VersionReq`,
lightweight tag, immutable stable release and its one expected asset.
`package::download_release_asset` repeats that resolution, fetches the exact
asset ID through the bounded raw-download helper, and checks actual byte length
and SHA-256 against immutable-release metadata. Its `DownloadedAsset` result
remains data; it does not establish provenance or authorize execution. The
focused package tests passed 11/11. The assembled worktree passed
`cargo fmt --all -- --check`, `cargo test --locked` (63 library tests passed;
305 CLI tests passed, 2 ignored; 22 bootstrap tests, 2 native-client integration
tests, and 1 testing-runtime integration test passed), and
`cargo clippy --locked --all-targets -- -D warnings`. Logs are
`/private/tmp/securefix-c80e-asset-fmt.log`,
`/private/tmp/securefix-c80e-asset-test.log`, and
`/private/tmp/securefix-c80e-asset-clippy.log`.

An anonymous, read-only public-API probe also resolved and downloaded the
existing legacy v0.2.44 archive as data: source/implementation
`1b35591e74eeae8fe848d16c6fcae0ba8fb75f6c`, publisher `1250079425`, release
`418770067`, asset `660228208`, 4,264,106 bytes, SHA-256
`d40309b8b574947bd9900e6996a804b38950749e7cf799161bec534cf68061b8`. The
bytes remained in memory; the probe did not execute, extract, or unpack them, or
qualify policy, a generic package format, or producer attestation. Local probe
logs are `/private/tmp/securefix-package-probe/probe.log` and
`/private/tmp/securefix-package-probe/probe-build.txt`; they are not persisted
CI evidence.

The local resolver remains partial: it does not acquire or authenticate the actual
reusable-workflow/composite-action defining revision, bind a producer run and
attestation to the source and asset before execution, or qualify pre-execution
checks in hosted scratch. The probe confirms metadata and byte-integrity shape
for one existing legacy archive only; it does not qualify the generic
policy-free publisher path or any separately justified bounded publication
adapter. The resolver is not wired into an operational caller. These
local checks do not close D01 or U03.

The disconnected `workflow::require_reusable_correspondence` helper in
[`src/workflow.rs`](../src/workflow.rs) is another partial D01 unit. It limits
caller YAML to 64 KiB and format-validates `caller_sha` and called
`implementation_sha` as separate full-SHA inputs. It checks the expected
publisher repository and reusable workflow path, the exact full-SHA `uses`
pin, and the matching `referenced_workflows` path/SHA. The helper does not
fetch or authenticate workflow-run references, retrieve or bind YAML bytes to
`caller_sha`, or confer execution authority. Focused tests passed 7/7 and
`cargo fmt --all -- --check` passed; an independent static review found no
further issue. The inspected `src/workflow.rs` snapshot has SHA-256
`fe8e832a6cd43976816359d559a7da847ad7b3c0d9940670aa16facd528bbeb1`. The
assembled worktree test run exited 0: 396 passed and 2 ignored (66 library,
305 CLI plus 2 ignored, 22 bootstrap, 2 native-client, and 1 testing-runtime
tests). Log: `/private/tmp/securefix-c80e-correspondence-test.log`. Clippy
exited 0; log: `/private/tmp/securefix-c80e-correspondence-clippy.log`.
This is local helper evidence only; it closes no authentication, source
acquisition, producer provenance, or execution-authority part of D01.

The separate 2026-10-21 read-only event trace confirms the caller/producer gap:
successful PR-target Approve run `39494262810` and Policy Check run `39494262697`
had `run.head_sha` at the PR head while their reusable references identified
base/main, and both had `pull_requests=[]`. Issue-comment Approve run
`39495004929` listed reusable references although its caller job was skipped.
The artifact API binds an artifact to a run but has no producer job ID; verify
the exact successful producer chain through the jobs endpoint on the same
attempt and bind the bounded artifact/manifest to that run and repository.
Neither references nor a matching artifact name closes this gate. D01 remains
open and blocks executable qualification until event-specific caller-source
and actual producer evidence pass fixtures and scratch.

The U04a parser checkpoint (2026-10-21) has local review and test evidence, but it does not close D02. An independent static review found no further code issue. `cargo test --locked instance_config` passed 10 tests. `cargo fmt --all -- --check` passed with no output. The full `cargo test --locked` run passed, with 2 ignored. `cargo clippy --locked --all-targets -- -D warnings` passed. The full-test log is `/private/tmp/u04a-cargo-test-with-gpg.log`; the Clippy log is `/private/tmp/u04a-cargo-clippy.log`. The focused test output and formatting output were not saved to separate files.

Earlier local attempts exposed corrected test setup failures. The first compiled focused run passed 6 of 7 tests because a fixture helper assumed `trusted_committers` was on one line. A later run passed 9 of 10 tests because an empty-root-field mutation placed `repositories` under `[exemptions]`. Both test helpers were corrected before the final 10-test pass. The first full-suite attempt failed because its narrowed `PATH` hid the existing GPG executable. `/private/tmp/u04a-cargo-test.log` records that failure. Adding the existing `/run/current-system/sw/bin` directory to `PATH` made the full suite pass; no package was installed or changed.

These results are local evidence only. The parser is not wired to authenticated protected-main configuration loading. The complete schema and reader/loading API remain unresolved, and no hosted scratch qualification has run.

The prior parser-consistency checkpoint records an independent review of the
internal identity-consistency checks and 13 focused `instance_config` tests,
including the separate [legacy-policy parity
fixture](../tests/fixtures/instance-config-policy-parity.toml). This evidence
covers only the disconnected parser and its fixture; it does not establish
authenticated configuration loading or operational policy externalization.

The 2026-10-21 workflow-role subunit adds a required closed map for `approve`,
`merge`, `policy_check`, `securefix`, and `release`. It requires each role when
any configured repository enables its capability, with `policy_check` required
for merge. It preserves configured path case and rejects duplicate paths after
ASCII lowercase normalization. An independent static review found no
actionable issue. The focused parser tests passed 17/17, and the assembled
worktree passed `cargo fmt --all -- --check`, `cargo test --locked` (73 library,
305 CLI with 2 ignored, 22 bootstrap, 2 native-client, and 1 testing-runtime
tests passed), and `cargo clippy --locked --all-targets -- -D warnings`. Logs
are `/private/tmp/securefix-c80e-roles-standard-fmt.log`,
`/private/tmp/securefix-c80e-roles-standard-test.log`, and
`/private/tmp/securefix-c80e-roles-standard-clippy.log`. These local checks do
not authenticate mapped files or qualify a protected-main reader or hosted
scratch operation.

### Proposed identity specification to qualify in D03–D05

Use these names consistently in the ADR and code; choose final type/field names there:

- `M`: captured protected-main commit used to retrieve bytes/history. It is a lookup snapshot, not deployment identity.
- `K`: configuration identity over exact bounded TOML bytes and authenticated instance repository ID/path/schema. Raw byte hashing is acceptable; comments then invalidate old authorization deliberately.
- `W`: canonical, role-sorted entries for the strict `[workflow_roles]` map of ordinary CLI operations: wrapper role/path/raw-byte digest plus its literal first-party pin and independently resolved package identity. Initial wrappers are canonical thin files with no local action, reusable workflow, script or client-controlled hook. Do not add a transitive local dependency closure. Repo-settings reconciliation and the trusted publisher are separate authority lifecycles, not ordinary roles. The current asset resolver proves metadata and byte integrity only; producer/source/run/signature proof remains open under D01.
- `E`: anti-replay epoch from relevant protected-main changes. Proposed ADR 0012 takes the newest first-parent change to an exact path in `P = {TOML path} ∪ {mapped role paths}`, using one raw path-history traversal over a complete `blob:none` commit/tree graph fetched at exact `M` with no depth. It has no commit-count cap. Provisional bounds include a 64 MiB object-store cap, 30 seconds per network Git child, 60 seconds total, and bounded output/current-blob reads; cap breach, incomplete/shallow graph or timeout fails closed. Prove add/remove/revert, merge, rename/delete, path-set, long-history, and resource-bound behavior without making unrelated source-commit count a deployment-maintenance requirement. Do not use timestamps, incomplete history results or simply M.
- `D`: domain-separated hash of authenticated instance identity, W and E. `A`: the command/request authority tuple `(K, D)`, always bound with exact PR head and replay/expiry data. Specify canonical field encoding/hash domains so different values cannot serialize ambiguously.

Retrieval must be read-only, repository-scoped and bounded, with authenticated expected branch/repository. Proposed ADR 0012 specifies the full filtered exact-`M` Git fetch, current TOML/wrapper blob batching, raw first-parent path-history parse, and final protected-branch recheck. Its bounds are provisional: cap temporary objects at 64 MiB, each network Git child at 30 seconds, total retrieval/history at 60 seconds, and each captured stream/current-blob batch at its stated byte limit. Reject on a cap, shallow/incomplete graph, malformed or truncated output, or head movement; never accept a partial identity. Cache only immutable package proofs, not current authorization. The method is proposed, not runtime-implemented or scratch-qualified; do not add a mirrored generation/version setting or commit-count maintenance requirement.

At request start capture A and configuration bytes once for an operation in the configured ordinary role map. At every such mutation boundary, independently read current authoritative branch state, reconstruct K/D and compare to accepted A; also recheck exact head, permissions, review, signatures and required checks as applicable. Pass snapshot digest/identity through jobs and validate it on receipt. Do not reread a different policy mid-operation and mix decisions. Current-state read failure is a failure to authorize, not permission to use a cached decision. Repo-settings and trusted publisher writes keep their separately owned authority and credentials.

Serialize controlled main mutations with existing `securefix-control` concurrency. Define per-target write ordering and expected-head CAS; do not claim cross-repository atomicity. Retain the existing exact-head owner command/review contract. A self-update merges under old A, validating the complete proposed successor beforehand, and ends privileged work after that successful merge. If a completion marker would require a post-merge write, design a bounded mechanism before implementation or omit that write; no general stale-authority exception. New authority requires fresh commands, including after a rollback.

## U01 — Capture the current contract and isolate production dependencies

**Inputs:** repository instructions, README/CONTEXT, merging/client/release/settings/migration/testing contracts, historical deployment evidence as dated context only.

**Actions:**

1. Capture source/main revision and actual active descriptor identity, runtime source/release/assets/policy digest, current Server workflows/local dependencies, test configuration and every configured Client pin/action `runtime-sha`. Read only; do not query administrator settings in ordinary operations.
2. Make an explicit dependency table: production event file → reusable/local action → CLI commands/inputs/outputs → credential/environment → required check names. Identify paths whose main merge affects production immediately today.
3. List Client variants across approval, merge, policy, Securefix/artifact intake and release routes. Record required protocol, signatures, events, permissions, lockfiles and critical PR/merge dependencies. Do not assume all nine historical callers still have identical pins.
4. Save known-good immutable sources/configuration/workflow blobs and available return-path evidence. Note retired bootstrap/repair cannot be fallback authorities.
5. Measure one representative current edit loop from available timestamps/usage: build, first result, fixture setup, CI/API waits, publication, activation, distribution PRs. Unknown token counts remain unknown.

**Deliverable:** inventory/evidence document and current-closure do-not-change list. **Proceed:** every production dependency and Client variant accounted for before shared operational edits or cutover. A direct scratch probe may start earlier once its selected route, candidate source/artifact, test-repository scope and affected checks are captured; it cannot change production. **Stop/return:** unknown or changed inventory means no cutover/shared operational edit; independent source work and bounded scratch probes continue.

## U02 — Settle contracts by dependency before trust changes

**Depends on:** U01 for production changes. The first scratch slice needs only its affected decisions; resolve D01–D09 as their dependent implementation and cutover units are reached. Do not gate the first functional probe on the complete map, release design, all-role inventory, reconcile planner or cutover mechanism.

**Actions:**

1. Map each policy/deployment/hardcoded field to external TOML, credential secret/reference, generic protocol constant, repo-settings desired state, or legacy-only removal. Explicitly include `renovate_merge_policy.json`, `SECUREFIX_POLICY_PATH`, default owner/repo/actor values and archive `repo-settings/` contents. Give every mapped value a required/missing/unknown-field rule.
2. Define strict TOML schema and config-path input semantics. Reuse existing TOML tooling if sufficient; inspect `toml_edit` features and typed parsing support before choosing the smallest necessary dependency adjustment. No custom TOML parser.
3. Define package/release metadata, source/provenance proof retrieval for actual composite/reusable invocation, supported request/config interfaces and fixed artifact layout. Do not put expected self-generated asset hashes inside their own source.
4. Freeze K/D/E, the strict ordinary-operation role map, canonical thin-wrapper shape, initial coherent Server pin rule, replay/command formats and every in-scope privileged API fence. Explain role additions/removals and wrapper changes; initial wrappers have no local dependency closure. Keep repo-settings and trusted publication as separate authority lifecycles.
5. Specify `[acceptable_clients]` SemVer grammar, distribution repo identity, official stable release proof and protocol negotiation/rejection. No source floor, ancestry rule or historic SHA allowlist as a replacement for the agreed range.
6. Define repo-settings structure-versus-pin normalization, signed exact-file PR behavior, stale/failed update repair and independent job scopes. Define Server Renovate grouping and scratch checks on candidate pins/configuration.
7. For the first vertical slice, specify one Client request path, its minimum required config, source-bound direct candidate, actor/repository/capability checks, exact-head/current-write behavior, and scratch-only credentials. Continue the wider protocol, all-role, cutover and return decisions before the units that depend on them. A declared downtime window is acceptable; do not require a full old/preparatory/new Client matrix or compatibility implementation solely for continuity.

**Deliverable:** a route-specific contract for the first probe, followed by the complete ADR, field map and test matrix for broad implementation; update domain terminology as appropriate. **Proceed:** the first probe has reproducible source/artifact, identity, config and head inputs; broader units proceed when their own contract is settled. **Stop:** an undecided affected identity/provenance/write mechanism blocks that route, not unrelated work. Design acceptance does not certify code or deployment.

### U02 executor decision cards

These cards constrain the ADR; they do not accept a schema or choose an unproved retrieval algorithm. The full-SHA YAML pin is the sole implementation selector. `securefix-server.toml` has no `[runtime]` or implementation-version `[server]`. `[acceptable_clients].version` is a SemVer `VersionReq`, not another selector or a SHA list.

**A — Field map and defaults.** Map every value below and any additional workflow/publisher constants discovered in U01. Missing required identity/policy fails closed; there are no account/repository defaults. Unknown TOML fields reject. Secret values stay in GitHub secrets; optional configuration may name a secret but cannot contain its value.

| Current source | TOML destination or disposition | Requiredness rule to encode |
| --- | --- | --- |
| `version` in `policy.json` and `.github/testing-policy.json` | Required `schema_version`, config format only | Required; reject unsupported values |
| `owner_id`, `deployment.owner_login` | Human-owner role, separate from the Server repository-owner role | Required for owner-command/review authority; no fallback |
| `deployment.repository_owner.{login,id}` | Server repository-owner role | Required; compare with authenticated repository metadata. The human owner and repository owner are separate roles, but may be the same principal when both identities match authenticated metadata. |
| `deployment.server.{repository,id,default_branch}` | Server instance identity in the instance section (not implementation `[server]`) | Required; reject authenticated-context mismatch |
| `deployment.client_app_id`, `deployment.server_app_id`; top-level `client_bot_id`, `server_bot_id`; `deployment.client_bot_login`, `deployment.server_bot_login` | Deployment App/bot identities | Required for enabled operations that use them; reject mismatch |
| `deployment.approval_reviewer.{login,id}`, `deployment.checks.{status_app_id,policy_app_id}` | Approval and required-check identities | Required for the corresponding gated write; no permissive default |
| `trusted_committers` | Explicit effective-committer policy | Required when commit authorization is used; empty must not mean allow-all |
| `sensitive_path_approval_exemptions.{users,github_apps}` | Explicit exception lists | Omission may mean empty only if schema says so; never inherit from trusted committers |
| `merge_controls_enabled` | Explicit merge policy | Required; omission cannot enable merges |
| `repositories[].{repository,capabilities,release,protect_tags,sensitive_paths}` | Consumer repository policy; per-repo paths may inherit only explicit `default_sensitive_paths` | Required repository/capability/tag policy; absent release disables release capability; reject inconsistent pairs |
| `default_sensitive_paths` | Explicit shared path policy | Required when sensitive-path policy is enabled; no account exceptions |
| `deployment.integration.{repository,id,default_branch}` | Authenticated scratch-only identity | No production default; absence disables scratch-only routes |
| `deployment.workflow_prefix`, `control_repository` | Legacy/test namespace and descriptor details | Omit from generic schema unless a reviewed protocol requires them; reject scratch identity in production |
| `deployment.release_branch` | Instance branch only if a retained independent operation requires it | Required only for that enabled operation; no compile-time fallback |
| `deployment.runtime_update_branch` | Legacy activation/distribution branch | Remove with that legacy flow; do not add to new TOML unless a separately identified new operation requires it |
| `renovate_merge_policy.json::renovate_merge_bot.{id,login}` | External Renovate merge-policy identity; remove compiled `include_bytes!` authority | Required when bot self-merge is enabled; otherwise disable that capability |
| `SECUREFIX_POLICY_PATH`, test fixture fallback, archive `repo-settings/` | Explicit protected-main config path relative to Server repo; fixtures scratch-only; settings templates stay with repo-settings | Reject path substitution outside authenticated instance context; do not package consumer policy/settings in generic release |

**B — Configuration loading.** Every trusted Server wrapper must supply the TOML path explicitly, relative to the authenticated Server repository root and protected-main snapshot; there is no implicit default path. Never accept a Client-selected repository/path or a PR's proposed file as production policy. Required values are capability-dependent only where shown above; otherwise reject absence. Optional lists can default empty only when that behavior is explicit in the schema. Preserve production and scratch identities/installations separately.

**C — Release proof and Client acceptance.** The proposed ordinary-run adapter uses the authenticated workflow-run API's repository, caller `path`, and `referenced_workflows[{path,sha}]`; it does not assume event `head_sha` identifies caller workflow source. The actual caller-source revision adapter remains open until positive/rejection fixtures cover each supported event. Initially support reusable workflow execution; a source-owned composite nested inside that verified reusable inherits its source identity, while standalone remote composite execution is unsupported. Do not rely on unverified `job.workflow_*` fields. Bind implementation SHA, trusted repository ID, source, stable SemVer, producer workflow/run/attempt, immutable asset ID and digest to the pin before execution; the metadata resolver's byte-integrity result is not producer/attestation qualification. `acceptable_clients` requires publisher repository identity and a parsed `VersionReq`; an unbounded minimum such as `>=1.4.0` is valid. Reject unsupported protocol even for a trusted future version, and allow prerelease/unreleased artifacts only through an explicit authenticated scratch path.

**D — Anti-ABA authority and coherent Server pins.** Reject whole-main SHA because unrelated source/docs merges would alter authority; reject current-bytes-only identity because a revert can revive old commands. Proposed ADR 0012 scopes `W` to configured ordinary CLI role wrappers and their package proofs; initial wrappers are canonical and contain no local dependencies. A required-CI inventory checks exact known ordinary token-minting and write patterns against the role map; it is not a universal audit of repository credentials. Repo-settings and publisher lifecycles stay separate. The proposed `E` uses a full `blob:none`, no-depth graph fetched at exact `M` and one first-parent raw path traversal over the TOML and mapped wrapper paths, with no commit-count cap. Provisional limits are 32 role paths; 256 KiB TOML and per wrapper; 4 MiB combined current bytes; 1 MiB metadata/history output; 5 MiB current-blob batch; 64 MiB object store; 30 seconds per network Git child; and 60 seconds total. Verify cap, shallow/incomplete graph, malformed-output, head-movement and merge/rename/delete/revert rejection behavior. This design remains proposed until the source inventory, exact algorithm, and hosted scratch are qualified. Initially require one coherent Server release and grouped Renovate updates; reject partial pin sets. Source/docs-only edits must preserve identity; relevant config/role changes and reverts must invalidate it. Recompute current ordinary authority before every in-scope privileged write.

**E — Reconcile and Client acceptance.** Preserve a verified compatible installed pin, including a newer Renovate pin; normalize structure/comments with that same pin. Reject unsupported structure/protocol. Missing/invalid pins get one reviewable managed-file PR against a verified approved compatible stable target; never auto-merge, centrally downgrade, or infer “stalled” from age, release availability, open PR, elapsed time or failure. An exceptional one-repository repair needs expected default head, explicit target SHA, independent proof and review. Highest-SemVer target selection stays open until complete bounded release enumeration and interface proof; never select from partial pagination. Define the new Client protocol and provenance; at cutover, reject old commands whose authority is stale. Do not require old/preparatory/new Client coexistence or success-path support.

**F — Cutover and conditional return.** Qualify the new Server + new Client end to end in scratch with direct source-bound artifacts before relying on a published generic package. Independently qualify the generic publisher against the policy-free archive and isolated credential model. Establish whether the existing reviewed lane can merge the exact coherent Server pin/TOML successor under current authority; if not, design a separately reviewed bounded migration executor only if proven necessary. Fence queued/in-flight old writes, reject stale commands, apply the exact head-fenced successor, and resume only fresh requests after the new Client canary passes. A temporary downtime window is acceptable. Self-update merge is terminal under old authority; bootstrap and repair stay retired. Rehearse any promised return route or mark it unavailable; a broken deployed pin has no assumed self-repair guarantee. No production experiment is a test fixture.

U02 exits only when an accepted ADR contains the field map, provenance acquisition, bounded authority algorithm, reconcile semantics, new protocol/rejection cases, exact cutover authority and conditional return. Parser code or local fixtures alone do not satisfy the gate.

## U03 — Fixed generic package and artifact-first development loop

**Depends on:** D01/D02 release boundary settled. **Inspect:** publishing/build workflows, setup/install/load-runtime actions, `src/runtime_archive.rs`, runtime verification and version-change gates.

**Actions:**

1. Add a new generic build/package path without changing legacy production loaders/publisher. Build binary from exact source, produce immutable candidate artifact and technical manifest. Exclude consumer policy and deployment repo-settings. Preserve archive bounds, duplicates/traversal/symlink rejection and executable checks.
2. Implement Rust verification of package/source/producer/platform/digests using settled D01. Let new pinned action/workflow select only its corresponding package; no runtime-selector input for production. Any scratch artifact input is explicit and unavailable to the normal production path.
3. Separate credential-free build, signing and publication. Never execute candidate or client hooks in a writer job. If preserving the predecessor needs embedded consumer bytes, isolate those in a legacy-only build target/feature or equivalent minimal packaging boundary; the generic executable must not contain those bytes or defaults, even if both builds share Rust helpers. Generic stable publication uses its own qualified implementation path; releasing it does not alter any instance YAML or descriptor.
4. Reuse one immutable candidate artifact across exact prepare/verify fixture runs. Add a focused bounded scenario only when existing harness cannot exercise the changed boundary; no arbitrary shell/CLI input or new test service.
5. Test positive package load plus wrong source/platform/producer, changed bytes, missing proof, missing asset and malicious archive; verify no mutable/build fallback. Test an old pin still loads its same binary after another release. These are generic package gates; they are not prerequisites for the separate direct-artifact first slice below.

**Deliverable:** generic package/loader plus saved package evidence. **Proceed:** source-to-binary binding demonstrated for each supported published execution form. **Return:** remove/fix the new package path; existing runtime/production closure remains unchanged. Do not send new archives to old publication assuming acceptance.

## U04 — Strict external configuration and authority fences

**Depends on:** D02–D05 settled; U03 for generic executable evidence. **Inspect:** `src/config.rs`, `src/policy.rs`, `src/api.rs`, control commands, request/review/receipt markers and all mutation APIs. The first vertical slice can validate its minimal contract before this full unit closes; do not route it through production handlers.

**Actions:**

1. Implement the agreed schema and bounded authenticated protected-main snapshot reader. Require explicit config path relative to Server instance root; reject missing fields, unknown fields, unsupported schema and invalid paths. Resolve instance identity independently of Client input/distribution checkout.
2. Route new-mode policy through the captured config, removing consumer values from the new generic package's execution path. Preserve legacy parsing unchanged in a narrow adapter until U11. Do not turn a test-only fixture fallback into production behavior.
3. Implement K/D/E and canonical identities per ADR; no whole-main authority hash. All multi-job inputs reference one verified snapshot. Prove freshness before privileged writes; preserve expected-head checks and existing operation-specific authorization.
4. Bind new commands/receipts/replay keys to A and exact PR head. Never translate legacy control commands into new authority approval. Audit each public mutation helper so a missed call site cannot bypass new current-authority checks.
5. Test config-only change without binary rebuild, source/doc-only merge identity stability, config/pin/local-helper/role changes, mixed pins, exact-content revert, replay, stale head, unknown current state and cross-instance/test config substitution.

**Deliverable:** new-mode external policy and write fence implementation, equivalent old/new authorization fixtures, mutation audit. **Proceed:** affected scratch success/rejection and independent readback; no stale writes. **Return:** leave new mode disabled for production and fix its path; do not change old active policy loading early.

### U05a — First hosted Server + Client vertical slice

**Purpose:** get one new Client path through the new Server in `testing-securefix-server` as the first functional proof. It does not depend on full U02/U03/U04/U05, generic release publication, U06/U07, or every feature/role being complete. Before execution, settle only the affected source/artifact, request protocol, required config fields, repository/actor/capability identity, exact PR-head/current-write fences and test-only credential scopes.

**Concrete slice:** use one disposable Client PR and one `policy_check` request. The new Client request path captures the exact PR head and sends its bounded request; the new Server validates that request against a valid explicit scratch config accepted by the existing strict parser and publishes the policy result for that head. Advance the PR head after capture and verify the stale request cannot publish a result for or otherwise mutate the newer head. Exercise the positive request and this affected rejection path only; additional routes remain later work.

**Actions:**

1. Build from the exact reviewed candidate SHA and reuse the immutable candidate artifact from its successful credential-free producer run. Before execution, bind the SHA, producer run/attempt, artifact ID/digest and `testing-securefix-server` identity. This direct source-bound path uses the documented owner-selected development threat model; it is not generic release or published-client proof.
2. Use the same source-bound candidate CLI for the new Client and Server path. Keep installation tokens repository-scoped to `testing-securefix-server`; do not pass production credentials, shared credentials or App private keys to the candidate.
3. Wire the disposable Client workflow, valid test configuration, PR/branch and any required scratch repository settings directly in the test repository. Create, edit, delete and recreate these scratch objects as needed. Scratch administrator authority remains test-only and outside ordinary Client/Server tokens. No repo-settings PR or reconciliation prerequisite applies to this first probe.
4. For GitHub behavior that remains uncertain, use a small focused scratch probe and record its exact event, run/attempt and resulting state; do not expand the first slice into a whole-feature or compatibility matrix.
5. Capture the request artifact and producer evidence, PR/head before and after, expected policy check, rejection reason, independent readback and cleanup. A fixture or PR creation without the new Client-to-Server result is not success.

**Deliverable:** one successful new Client → new Server `policy_check` result and one stale-head rejection, with exact source/artifact and state evidence. **Proceed:** the selected path and affected rejection work in the hosted scratch repository while production closure stays frozen. **Return:** fix only the affected implementation and disposable scratch wiring; unrelated D/U units remain open.

**Hosted evidence (2026-10-21; narrow qualification).** Candidate Rust source was
`961ffff5ab30be4a0197c64c9a4170515b787f5f`, built successfully by run
[#39563689101](https://github.com/civitaspo/securefix-server/actions/runs/39563689101)
as `candidate-runtime` artifact `12328813435` (4,549,853 bytes; SHA-256
`3e8ff5b90550f70308f240fde77d058aeb37e700211db044a1e66874a7196ca6`). The
attestation signer was the separate reusable-workflow revision
`93f0c7b4c35e9946a899c2fdf5b09529894ac067` at
`.github/workflows/request-producer-probe.yml`; it did not change the Rust
source or require a rebuild. Scratch wrapper `policy-check.yml` was on
`testing-securefix-server` main `0fbe835ef9b27f36f74a5bf27d9f3d6459de38f0`.

Producer run
[#39564989587](https://github.com/civitaspo/testing-securefix-server/actions/runs/39564989587)
created `native-request-proof` artifact `12328924468` (7,459 bytes; SHA-256
`037069a2d049e123c2540bf898ef1aaea8997a048b1861a6c9eb2eb452905bda`),
containing the 746-byte manifest and 11,271-byte local attestation bundle. The
manifest binds run/attempt `39564989587/1` and PR #365 head
`744dee8dc68da2aa8a8fa4271e9f37b7bedfba76`. Consumer run
[#39565253920](https://github.com/civitaspo/testing-securefix-server/actions/runs/39565253920)
successfully verified and published check `securefix-native-request-policy-check`
ID `119106008516` (GitHub Actions App 15368 (scratch `GITHUB_TOKEN`)) on that exact head.

For the rejection, signed commit `d7d9ab8c538fd853dc7b29d6ae5a9d2fb3527ae0`
advanced the same PR after capture. Replaying the same artifact in run
[#39565408082](https://github.com/civitaspo/testing-securefix-server/actions/runs/39565408082)
failed with `native request PR is closed, retargeted, or has a different head
or identity`. Independent readback found no native check on the new head and
exactly one successful check on the captured old head.

An earlier producer run `39564186380` uploaded a manifest without its bundle
because the workflow passed `bundle-path` as an action input instead of copying
the action output. Consume run `39564377455` failed on the missing bundle. The
workflow-only fix is the `93f0c7b` signer revision above. This qualification
covers this `workflow_dispatch` fixture and stale-head fence only; full config
and history behavior, generic release/source proof, Client signature policy,
owner-review approval, and other event wrappers remain unverified.


## U05 — Reusable Server/Client implementations and release-range acceptance

**Depends on:** U05a for the initial path shape; U03/U04 and D01/D06 for generic published execution. **Inspect:** feature entrypoints, client action, `src/request.rs`, `src/policy_check.rs`, `src/securefix_gate.rs`, `src/release.rs`, `src/workflow.rs` and integration source qualification.

**Actions:**

1. Extract candidate reusable feature workflows with typed inputs/secrets and job isolation matching current contracts. Retain event/job/check semantics at thin instance wrappers; define config path explicitly. Invoke self-revision local actions correctly; do not use relative caller checkout accidentally.
2. Make Client implementations execute their fixed verified binary. Define actual producer/revision/release proof in the request envelope and independently validate it at Server. A new protocol must have an explicit discriminator and strict parser; never reinterpret legacy `workflow_sha` or translate an old command into new authority. The new mode may reject the legacy protocol.
3. Validate actual implementation repository identity, revision/pin, official stable release, source/asset/producer proof, configured SemVer range and supported protocol. Reuse verification across routes within a request without caching current authorization across requests.
4. Cover approval, merge, policy, Securefix intake, release-PR/sync/tag and any additional inventoried feature. Preserve canonical wrapper, effective-committer/signature, archive, actor/capability and release-state checks. Do not replace the old equality check with a version-string comparison.
5. Add scratch-only prerelease/unreleased qualification explicitly scoped by authenticated scratch deployment and artifact proof. Requests cannot enable it in production.
6. Test accepted minimum/newer stable/in-range unbounded version, optional upper bound, below minimum/out-of-range, wrong repo/source/asset, forged version, prerelease/draft/unreleased, unsupported protocol, broadened wrapper and failed checks. Prove ordinary new Client version acceptance requires no TOML SHA edit or Server binary rebuild.
7. Extend hosted end-to-end coverage only to the remaining features and rejection cases required before deployment; do not make every route a prerequisite for the first slice.

**Deliverable:** reusable release units, thin scratch wrappers and route-wide proof. **Proceed:** each affected published path passes its hosted evidence before cutover. **Return:** fix only new implementation/scratch wrappers; no production handler replacement.

## U06 — Independent repo-settings workflow deployment/reconcile

**Depends on:** D08 and the tested U05a workflow/config shape for the selected path. Adopt that direct scratch state now and prove convergence; broader U05 templates/protocols are added as their caller routes are implemented. **Inspect:** `src/settings.rs`, `src/distribution/`, generator templates, `.github/workflows/repo-settings.yml`, lockfile helpers and caller migration lane.

**Actions:**

1. Encode the verified Client workflow/configuration and any owned repository settings in repo-settings desired state. Render the managed state from that source and run reconciliation again against the converged fixture; require zero diff. Then separate desired structure (files/permissions/events/inputs/roles) from acceptable pin/update policy and reuse bounded canonical generators/validators, managed-file ownership, signatures, expected-head and resulting-default-branch checks.
2. Inspect existing pin by verified release contract. Preserve a valid newer Renovate update while repairing structure. For a missing or invalid pin, propose the exact compatible target chosen under D08. Do not infer a version-repair obligation from age, release availability, an open PR, elapsed time or a failed run. A template's old pin alone is never a downgrade reason.
3. Prepare signed managed-file PRs only. Repeat reconcile with a converged fixture and assert zero diff. Reject unrelated file changes, stale heads, Client-authored structural mutations and broadened permissions.
4. Keep repository administrator settings job and workflow PR writer in distinct jobs with separate tokens, no secret inheritance, hooks or outputs that leak credentials. No administrator settings preflight in PR/merge/release operations.
5. Remove release/pub/activation coupling only for the new path; retain the frozen current production closure until cutover. Retire old readers/callers only through the reviewed migration plan; a caller may be suspended until updated. Do not auto-dispatch all Client PRs on OSS release and do not auto-merge reconcile PRs.

**Deliverable:** independent repo-settings reconcile and job-scope contract. **Proceed:** missing/changed permissions/events, failed-update repair, newer-pin preservation, idempotence and exact-file rejection pass in scratch. **Return:** pause reconcile PR creation; keep existing Client files and runtime operational.

## U07 — Renovate instance updates and candidate-deployment checks

**Depends on:** U05/U06. **Inspect:** existing Renovate configuration/policy and required CI.

**Actions:**

1. Use full literal SHA `uses` pins with verifiable `# vX.Y.Z` comments understood by Renovate's GitHub Actions manager. Verify extraction against the installed Renovate version/config rather than assuming it handles reusable/composite/nested paths alike.
2. Group all first-party operational Server pins into one coherent update PR. YAML alone selects implementation; TOML contains no duplicated runtime version. Existing third-party action updates remain separate where appropriate.
3. On a Server pin PR, validate canonical successor closure and run the affected scratch matrix with exact candidate pin/config snapshot. Execute proposed code/config only in test scopes; production processing of that PR still uses current deployed policy/authority.
4. Require exact-head scratch evidence, signatures, owner approval where required, required checks and ordinary serialized merge. Do not grant Renovate a special authority to bypass these. Existing non-major/major and bot effective-committer rules remain until explicitly reviewed policy changes.
5. Test Server and Client update PR extraction, stable version comments, grouped Server consistency, partial-pin rejection, stale scratch evidence after head change and self-update's terminal merge semantics.

**Deliverable:** Renovate + CI update contract and passing scratch PR evidence. **Proceed:** normal updates need only their PR processing, without central SHA edits/distribution. **Return:** keep installed pins; fix/close the proposed update. OSS release remains available without automatic deployment.

Renovate documentation: [GitHub Actions manager](https://docs.renovatebot.com/modules/manager/github-actions/). A source pin without usable version tracking is not completion of this unit.

## U08 — Qualify the new-stack cutover and conditional return

**Depends on:** U03–U07 and D07/D09. Qualify the generic publisher and exact authorization transition separately. A declared downtime window is acceptable; old Client coexistence is not a gate.

**Migration direction (2026-10-21).** This supersedes the earlier zero-downtime approach: old callers may be unavailable during cutover. No descriptor-era runtime bridge, full old/preparatory/new Client matrix, preparatory Client, or permanent legacy-protocol acceptance is required solely for continuity. Keep provenance, credential isolation, exact current-authority/head fences, in-flight write checks and stale-command rejection.

**Cutover shape:** First pass the new Server + new Client end to end in `testing-securefix-server` with direct source-bound artifacts. Then qualify generic publication for the policy-free archive and establish the exact authority that can merge the coherent Server pin/TOML successor. The existing publisher and ordinary merge lane may not support that transition; prove their behavior in scratch. If no existing reviewed lane can perform it, propose a separately reviewed bounded migration executor only when the authorization gap demonstrates it is necessary. Do not add a runtime bridge, preparatory Client or full Client-version matrix solely for old-client continuity.

### Owner-authored source PR route

Source inspection on 2026-10-21 found an ordinary lane for owner-authored Server source PRs in the [approve](../.github/workflows/approve-request.yml) and [merge](../.github/workflows/merge-request.yml) entrypoints and the Rust request/approval/merge path ([request](../src/request.rs), [approval](../src/approval.rs), [merge](../src/merge.rs)). The owner `/approve` command is revalidated against the owner identity and exact PR head/current control; it authorizes the request and waives only the additional sensitive-path owner-marker condition. It is not a native GitHub review. Signature verification, trusted effective committer, provenance, stale-head and control checks remain in force. A separately configured bot review is required for that exact head/control.

The owner must then issue a separate `/merge`; the merge path requires current checks, the Securefix policy result bound to the accepted head/control, GitHub `reviewDecision=APPROVED`, the exact configured bot review, and expected-head CAS ([merge checks](../src/merge.rs)). The code does not establish that a separate native owner-authored GitHub review is a general requirement.

Changed `control/active.json` uses the distinct server-bot activation contract in [control validation](../src/control_commands.rs); the ordinary owner-authored source-PR lane does not activate descriptors. Historical [PR #120](https://github.com/civitaspo/securefix-server/pull/120) and its [test-plan record](testing-workflows-plan.md) are precedent, not current certification. The supplied AGENTS text is an older snapshot (generation 4/v0.2.32); the dated [development-loop inventory](development-loop-inventory.md) records the later captured readback, generation 8/v0.2.44. Treat that inventory as point-in-time evidence, not permanent certification. This source trace did not inspect privileged repository settings or recertify current live state. The new architecture still requires fresh scratch rehearsal of this route and the coherent pin/config self-update.

### Self-PR checkpoint

This is a scratch acceptance gate; this guide does not itself authorize a PR or merge. Pass both self-update cases and their post-merge freshness/return checks before U08 closes:

| Case | Required exercise | Evidence to record |
| --- | --- | --- |
| Source-only Server self-PR | Use the supported current lane to merge a Server source change without changing instance configuration or literal pins. Verify that the deployed pin still selects the same fixed binary and the source-only change leaves new deployment identity unchanged. | Exact PR head, signed author/effective committer, review/check results, resulting default-branch head, and identity readback. |
| Coherent pin/config self-PR | Under the current authority, validate and merge one coherent set of first-party Server pin changes with its protected-main TOML successor, through the existing reviewed lane only if scratch proves that exact route works; otherwise exercise the separately reviewed bounded executor. The merge ends the old authority's write sequence. | Exact candidate/configuration identity and PR head, package/protocol and scratch evidence, review/check results, expected-head result and independent readback of merged pins/configuration. |
| Post-merge freshness and conditional return | Make no further writes under the old run. In a new scratch attempt, prove stale old commands and queued writes reject, then start a fresh run under successor authority and prove it succeeds. Exercise a broken-pin return only if the route is available and state its prerequisites. | Old-command/write rejection, fresh-run result, resulting state, exact return PR/route and prerequisites, or explicit evidence that no return route is qualified. |

A scratch fixture PR, local test, or successful PR creation is insufficient. The source trace identifies an ordinary owner-authored source-PR route; do not record that code path as absent or unknown. Its current hosted availability, the new architecture's pin/config self-update route, and any promised return route still need scratch evidence. If the reviewed transition route, current-write fencing, or any promised return path is unproved, keep U08 open. Do not revive bootstrap/repair or invent a bypass. The cutover may declare and schedule an outage; it may not weaken authority, provenance, review, head checks or credential isolation.

**Actions:**

1. Keep the current production dependency closure frozen during implementation and scratch work. Do not require old Clients to continue working after the declared cutover window.
2. Use one source-bound direct candidate artifact to prove new Server + new Client end-to-end paths in scratch, including affected success and rejection cases, before relying on a published generic release. Candidate runs keep existing test-only scopes and credentials.
3. Independently qualify the generic publisher/archive, producer/source proof and credential isolation. Do not assume the existing legacy publisher accepts a generic policy-free archive; do not hide a failed normal publication behind a manual release.
4. Inspect and scratch-test the exact coherent Server pin/TOML self-update route. Use the existing reviewed owner lane only if it accepts that exact successor and preserves expected-main/head CAS. If not, specify a separately reviewed bounded executor only when this trust/authorization gap proves it necessary. Keep allowed files, full current authority, expected head, actor/signature/required checks, protected environment, scopes and serialized mutation lane explicit.
5. Plan the fenced coherent Server authority transition: stop admission to old request/writer lanes; identify queued/in-flight accepted writes and prove the actual write rechecks current full authority and exact head; revoke or reject pending old commands; merge the complete Server pin/TOML successor via the qualified route with expected-main and exact-PR-head CAS. Stopping triggers alone is insufficient. This is not a claim of an atomic cross-repository transaction. Do not delete `control/active.json` first or provide any post-cutover old-authority exception.
6. After the new authority is active, deploy a new Client canary, prove fresh authorized requests and the Server's own self-update under the new authority, then resume fresh request processing. An optional pre-update of Client pins is permitted only if the exact old validator accepts it in scratch; it is an optimization, not a prerequisite. Old Clients may fail during the declared window or remain unsupported until updated.
7. Rehearse the known ordinary owner-authored source-PR route described above. Source inspection establishes that route in current code, not current live availability. Confirm exact-head owner command, configured bot review, signatures/effective committers, required checks and CAS in scratch. Keep descriptor activation separate; do not revive retired repair or invent a bypass. Then rehearse source-only self-PR, coherent Server pin/config self-PR, relevant authority change during an in-flight request, exact revert and fresh-command handling. Existing required check names/events/environment/token isolation remain intact.

Explicitly classify the legacy distribution, control-activation, caller-migration, and bootstrap/repair writer lifecycles; the five ordinary roles do not cover them automatically. Before cutover, prove queued/in-flight writes and owner-dispatched old writer lanes are fenced or retired through the exact reviewed transition. An unchanged `control/active.json` alone is insufficient. Keep D03/D07/U08 open until this evidence exists; the guide selects no mechanism and authorizes no production disablement.
8. Rehearse any promised return to a known-good deployment and state its availability conditions. Simulate a broken proposed pin in scratch and document which failures still allow the running lane to merge a return and which disable it. Any independent recovery path needs its own reviewed authority and actual proof; no new bypass/native auto-merge/direct-write shortcut.
9. Save affected feature successes, rejection states, final release checks/assets where relevant, failed attempts, independent state readback and bounded cleanup. Keep scratch serialization separate from the production mutation queue.

**Deliverable:** cutover runbook with exact immutable artifacts/pins/configuration, publication evidence, fenced transition route, old-command rejection, declared downtime window, self-update and any conditional return prerequisites. **Proceed:** new-stack scratch success, generic publisher qualification, authorized exact-head transition, stale-write rejection and promised return routes demonstrated. **Stop:** if authority/provenance/fencing is unproved; do not cut over. A cutover does not require zero downtime or old-client coexistence.

## U09 — Coherent Server cutover under explicit rollout authorization

**Depends on:** U08 complete and reviewed. Production rollout is a later operation, not part of a documentation edit.

1. Recapture actual current authority, Client inventory and dependency closure; compare with rehearsal. Stop on unexplained drift. Do not request more administration scope to inspect settings.
2. Publish the verified generic release only after its publisher, archive, source/provenance and credential-isolation contract is qualified; publication alone does not change production.
3. Optionally pre-update Client pins only if the exact current validator and authorized migration lane accepted that sequence in scratch. The new Client need not be accepted by the old Server; do not require dual protocol support.
4. Quiesce old request/writer admission and fence queued/in-flight writes. Use the qualified existing reviewed lane or separately reviewed bounded executor for the exact coherent Server pin/TOML transition, with current-authority recheck and expected-main/head CAS. Keep credentials, events, checks and serialized concurrency intact; no arbitrary bypass or delete-descriptor-first path.
5. After the merge establishes new authority, old requests/commands must fail closed. Canary the new Client and run fresh authorized requests under the new Server. Do not reuse old reviews or commands for a new head/configuration; no follow-on old-authority write.
6. Resume fresh request processing only after the canary passes. Stop rollout on failure; use a rehearsed return path only if its prerequisites hold, otherwise report it unavailable and follow reviewed recovery policy. Do not repeatedly mutate production to diagnose.

**Deliverable:** exact cutover PR/head, source/release/config/deployment identities, declared downtime, old-write fencing and observed results. **Proceed:** fresh authorized operations work through the new Server + new Client canary. Unsupported old callers may remain suspended until updated or retired. **Return:** a known-good configuration/pin PR under functioning authority only when available; otherwise report the unavailable condition. Never claim unconditional self-repair.

## U10 — Canary and optional cohort Client rollout

**Depends on:** new-stack canary readiness, U06/U07 and U09. Cohort rollout is optional; no old/preparatory/new compatibility matrix is required.

1. Select owner-approved low-impact canary and preserve its previous qualified pin/config/protocol evidence. Structural deployment changes use repo-settings PRs; ordinary version changes use Renovate PRs.
2. Review exact owned files, lockfiles, signatures/checks and head; do not auto-merge distribution/reconcile PRs. Run fresh affected feature requests after the authorized merge.
3. On failure stop subsequent cohorts, investigate evidence and suspend the affected caller or apply only a separately qualified Client return/forward fix. Do not claim that unmigrated old Clients remain functional under the new Server.
4. Expand small cohorts only after the prior cohort's relevant paths succeed. Record callers still unsupported, suspended or retired, plus pending old-authority work. Keep any remaining legacy reader/writer bounded by explicit removal conditions.

**Deliverable:** per-Client deployed pin/protocol and evidence ledger, any failed-cohort return evidence, and explicit unsupported callers. **Proceed:** expand only after affected new-client paths pass; legacy cleanup waits until no active reader/writer/caller remains. **Return:** use only a qualified per-Client pin PR or forward fix; no old-release compatibility guarantee is assumed.

## U11 — Remove replaced legacy authority and prove routine independence

**Depends on:** U10 caller ledger and explicit legacy-retirement gates.

1. Search readers and generated callers, not only filenames. Start with `rg -n 'control/active|control_id|load-runtime|runtime-sha|SECUREFIX_POLICY_PATH|renovate_merge_policy|include_bytes!' .github src docs policy.json .github/testing-policy.json`; inspect every match and generated template/test reference. Repeat targeted searches for renamed aliases/types found in the first pass. Historical documents can remain clearly dated; executable/generator references cannot.
2. Reject legacy production request commands and revoke pending old-authority work before deleting its authority. Confirm no active deployed reader/writer/caller remains; never silently rebind old commands.
3. Remove descriptor/loaders, legacy bundled-policy packaging/overrides, embedded consumer Renovate policy and old activation/distribution coupling only after their respective no-active-reader/writer/caller conditions. Remove any adapter or success-path test used solely to guarantee zero-downtime old-client support; retain focused stale/legacy-command rejection, replay and current-write-fence tests. Preserve independent release/provenance verification, external config, exact-head/authority fences and repo-settings structural deployment.
4. Update README/CONTEXT/AGENTS, migration, configuration, client/merge/release/settings/testing contracts to implemented facts. Do not rewrite historical reports as present evidence. Remove temporary adapter flags and old scenarios with their retired interface; retain meaningful regression tests for rejection/replay.
5. Prove a second generic release leaves running instances unchanged until their own pin PRs; prove Server/Client Renovate updates independently, TOML policy-only change without release, unbounded-range Client update without SHA-list edit and reconcile after a newer valid pin.
6. Compare edit loop with U01 using measured builds/fixtures/waits/publications/PRs; report unavailable timing/token data. Stop adding abstractions when the agreed independence and security contracts work.

**Deliverable:** cleanup PR(s), no-live-reader evidence and before/after loop measurement. **Done:** generic fixed releases, external policy, independent instance pins, range-based verified Client acceptance, stale-authority rejection, normal self-update and independent reconcile all demonstrated. **Stop:** retain any still-required legacy component explicitly; do not delete `active.json` first or call partial cleanup complete.

## Minimum evidence ledger

For each implementation unit and hosted scenario record:

| Field | Required content |
| --- | --- |
| Classification | Source inspection / local test / direct artifact scratch / published scratch / authorized production observation |
| Sources | Worktree/candidate SHA, actual defining reusable/action revision, caller wrapper revision and exact PR head |
| Package proof | Release version/source, producer workflow/run/attempt, immutable artifact or release/asset IDs and digests |
| Authority | Instance repo ID, captured M, configuration path/digest K, closure/pins D, epoch evidence E, legacy control if explicitly applicable |
| Execution | Exact actual scenario inputs, prepare run, reused fixture/artifact bindings, expected success/rejection and run URL |
| Result | Required checks/review head, independent resulting state, denied-write evidence, affected release assets if applicable |
| Failure/cleanup | Original failure/cause, justified retry, remaining fixtures and verified run-owned cleanup |
| Gate | Passed / blocked with missing proof; next allowed unit and tested return-path conditions |

Do not invent IDs, results, CLI flags or workflow inputs to fill a row. If an expected capability does not exist, inspect its actual dispatcher/contract, add the bounded capability in a reviewed unit if needed, and only then execute it. A smaller model should escalate a demonstrated design gap, not expand authority to make the plan executable.
