# Independent implementation releases and instance deployments

Keep Rust and one repository. Release generic Securefix Server and Client implementations as immutable reusable workflows/composite actions with their corresponding binaries. Deploy each instance through reviewed YAML pins, keep its policy external, and allow existing Renovate configuration to propose ordinary Server and Client pin updates. Develop and test in `testing-securefix-server` without changing the working production deployment.

This replaces the earlier plan to retain a central dynamic runtime selector and compile a client-source compatibility list into the executable. Those are not the target architecture. `control/active.json` remains authoritative for the existing deployment until its responsibilities have been replaced and verified; deleting it is a final cleanup step.

This is a design and execution plan, not evidence that the current code implements it. The source inspection was captured at `6287b76f24d5f7023e84cd932bc84437c417447e`; see the dated [development-loop inventory](development-loop-inventory.md). This is a point-in-time inspection, not live deployment certification; recapture sources and deployment state before implementation. No production cutover, publication, remote test, owner command or recovery operation is authorized merely by this document. Follow the [execution guide](development-loop-execution-guide.md) for bounded implementation units, unresolved decisions and stop conditions.

## Lifecycle and authority

| Lifecycle | Owns | Changes when |
| --- | --- | --- |
| OSS implementation | Generic Rust validation/business logic, reusable workflows, composite actions, release verification and protocols | A reviewed source change is released |
| Server instance | Thin event workflows, literal Server pins, external configuration path, credentials and environments | Its reviewed deployment/configuration PR merges |
| Client repository | Thin Client workflows/actions and their literal pins | Its reviewed Renovate or structural deployment PR merges |
| repo-settings | Desired repository settings and independently managed Client workflow structure/reconciliation | Its own reviewed desired-state/deployment flow runs |

The implementation repository may also host an instance. Merging Rust source, documentation or a new OSS release must not select new production code. A pin change remains an explicit reviewed deployment change; publication must not trigger descriptor activation, central Client allowlist edits or bulk distribution.

Rust continues to own validation and policy decisions. Workflow/action code only passes events/inputs, fetches verified binaries and configuration, isolates credentials and invokes Rust. Do not move policy into shell, Python or github-script, introduce TypeScript, split the repository, build a general workflow interpreter or split every CLI subcommand into an action.

Use reusable units comparable in scope to `csm-actions/securefix-action`: a Client request action, Server approval/merge processing, Securefix request processing, and release processing are candidate boundaries. Confirm boundaries from credential/event contracts in U01; keep features together when separating them only adds artifact handoffs. Composite actions cannot define job-level credential isolation; use reusable workflows where separate jobs/environments are required.

## What is true today

| Source | Observed coupling to migrate |
| --- | --- |
| `.github/workflows/approve.yml`, other production entrypoints and local actions | Main-side orchestration can change independently of the descriptor-selected executable |
| `.github/actions/load-runtime/load.sh`, `src/control.rs`, `src/api.rs` | Ordinary operations read `control/active.json`; writes recheck its full identity |
| `.github/workflows/publish-runtime.yml`, `src/control_commands.rs`, `src/runtime_archive.rs` | Legacy publication/activation expects executable, bundled `policy.json`, source and archive bindings; publication also packages `repo-settings/` |
| `src/config.rs`, `src/policy.rs`, `policy.json`, `.github/testing-policy.json` | Deployment identities and policy are loaded from adjacent/bundled policy, with explicit overrides/test behavior to inventory |
| `src/config.rs`, `src/renovate_merge_policy.json` | Renovate authorization policy is compiled into the executable |
| `src/request.rs`, `src/policy_check.rs`, `src/release.rs`, `src/securefix_gate.rs` | Existing protocol and provenance checks couple client workflow source/runtime source/control; `workflow_sha` is not simply a new Client implementation identifier |
| `.github/actions/client/action.yml` | The old action requires `runtime-sha` and checks it against the active runtime |
| `src/distribution/`, templates | Caller generation targets active runtime source and is part of the legacy promotion/distribution lifecycle |
| `.github/workflows/repo-settings.yml`, `src/settings.rs` | Existing settings reconciliation must be separated from the managed-workflow PR writer's credentials and lifecycle |
| `src/integration/`, candidate workflows | Existing artifact-based probes can shorten iteration; exact supported combinations still need inspection |

These are code-inspection findings, not fresh deployment certification. Inspect hardcoded actor/repository identities in workflow loaders/publishers as well as Rust. Do not assume moving `policy.json` alone makes the release generic. Preserve current contracts until a reviewed transition explicitly replaces them.

## Agreement traceability

The eleven agreed constraints map to the plan sections and execution gates below. A mapped gate remains open or partial until its evidence is recorded; this table does not certify implementation or authorize a production change.

| Agreement | Plan coverage | Unit / gate |
| --- | --- | --- |
| 1. Separate OSS, Server instance, Client and repo-settings lifecycles | [Lifecycle and authority](#lifecycle-and-authority); [Independent repo-settings reconciliation](#independent-repo-settings-reconciliation) | U01; D05/D08 |
| 2. Literal YAML full-SHA implementation selector with source/provenance/digest proof; no fallback or TOML duplicate | [Immutable implementation contract](#immutable-implementation-contract) | U03; D01 |
| 3. Credential-bounded reusable orchestration; Rust owns policy | [Lifecycle and authority](#lifecycle-and-authority); [Immutable implementation contract](#immutable-implementation-contract) | U03/U05; D01/D06 |
| 4. Independent Server/Client implementation pins and reviewed deployment changes; no new update automation | [Independent repo-settings reconciliation](#independent-repo-settings-reconciliation); [Staged delivery and migration](#staged-delivery-and-migration) | U06/U08; D05/D08 |
| 5. Externalize consumer policy, including embedded Renovate policy, without account defaults | [External configuration and Client acceptance](#external-configuration-and-client-acceptance) | U02/U04; D02 |
| 6. Protected-main `securefix-server.toml`, path relative to Server root; no `[runtime]` or implementation `[server]` | [External configuration and Client acceptance](#external-configuration-and-client-acceptance) | U02/U04; D02/D03 |
| 7. `[acceptable_clients]` publisher identity + `VersionReq`; stable provenance/SHA proof, protocol rejection and explicit scratch | [External configuration and Client acceptance](#external-configuration-and-client-acceptance) | U02/U05; D01/D06 |
| 8. Replace `active.json` responsibilities with current authority, exact head and fresh write recheck; never hash all main | [Replace authority before removing the descriptor](#replace-authority-before-removing-the-descriptor) | U02/U04; D03/D04/D05 |
| 9. Independent repo-settings structure reconciliation, PR-only and separate admin/writer credentials | [Independent repo-settings reconciliation](#independent-repo-settings-reconciliation) | U06; D08 |
| 10. Freeze production closure through scratch; qualify a reviewed cutover, allow a declared downtime window, and retire legacy after no active readers/writers/callers remain | [Staged delivery and migration](#staged-delivery-and-migration); [Availability and recovery acceptance](#availability-and-recovery-acceptance) | U08–U11; D07/D09 |
| 11. Separate facts, agreement and uncertainty; specify per-unit evidence, cutover fences, retirement conditions and conditional return; no production experiments | [Completion and evidence](#completion-and-evidence); [Staged delivery and migration](#staged-delivery-and-migration) | U01–U11; all D gates |

## Immutable implementation contract

```text
Server instance event workflow
  -> Server reusable workflow @ literal full SHA  # vX.Y.Z
     -> corresponding fixed, source-bound Rust binary
Client repository workflow
  -> Client reusable workflow/action @ literal full SHA  # vX.Y.Z
     -> corresponding fixed, source-bound Rust binary
```

The pin is the implementation selector. No implementation version is duplicated in TOML. A pinned old implementation must never consult current central configuration to select a different executable. Instance policy can change; the binary associated with a pin cannot.

Before implementation, freeze a release contract connecting the defining workflow/action revision, source, stable SemVer tag, immutable release, producer workflow/run, archive/asset IDs and digests, and supported protocol/configuration interfaces. A source-resident package manifest may identify release version, platform asset names and producer paths; it is package metadata, not a deployment selector. Resolve source and asset digest through independently verified release/attestation evidence; do not create a source/archive self-hash cycle.

Use a credential-free build and isolated trusted signing/publication jobs. Generic executables and archives contain no consumer policy/defaults or deployment-specific repo-settings payloads; archives may contain technical release metadata/licenses. Any necessary legacy build keeps embedded consumer bytes outside the generic build. Verify the actual asset and executable before use. No execution fallback to main, mutable tag, latest release, local source build or unverified cache is allowed. A digest-verified cache of the same immutable asset is acceptable; missing proof fails closed. Scratch can explicitly select immutable unreleased build artifacts under its existing owner-selected-code threat model.

The proposed D01 adapter treats authenticated workflow-run references as correspondence data only. A 2026-10-21 read-only event trace found PR-target `run.head_sha` at the PR head while reusable/local-loader references identified base/main; successful PR-target runs `39494262810` and `39494262697` had `pull_requests=[]`. Issue-comment Approve run `39495004929` listed reusable references although the caller job was skipped. A subsequent scratch qualification verified native attestation for one `workflow_dispatch` policy-check request: the signed reusable at `93f0c7b4c35e9946a899c2fdf5b09529894ac067` produced a local-bundle attestation, while the source-bound Rust candidate remained at `961ffff5ab30be4a0197c64c9a4170515b787f5f`. The exact run/artifact/head evidence is in the [execution guide](development-loop-execution-guide.md#u05a--first-hosted-server--client-vertical-slice). This qualifies that fixture path, not generic Client release/source provenance or `pull_request_target`/`issue_comment` callers.

[ADR 0013](adr/0013-native-request-producer-proof.md) records the native attestation contract and its narrow scratch qualification. D01 remains open for generic published execution and unsupported event paths.

## External configuration and Client acceptance

The proposed configuration entry point is `securefix-server.toml`:

```toml
schema_version = 1

[acceptable_clients]
repository = "example/securefix"
version = ">=1.4.0"

[policy]
# Deployment-specific authorization, not implementation selection.
```

This is a conceptual shape, not the complete implementable schema. The first scratch slice resolves only the fields its selected route needs under the existing strict parser, using an explicit valid fixture; do not add a second parser, reduced schema or permissive default for speed. Complete U02 field mapping still classifies every current field before broad U04/U05 implementation. Necessary instance identities, repository/branch information, workflow roles, checks and credential references remain instance configuration according to their meaning. Secret values remain in GitHub secrets. There is no `[runtime]`, no implementation-version `[server]`, and no transplanted active descriptor. The disconnected parser has independent consistency review and 17 focused tests, including a separate [legacy-policy parity fixture](../tests/fixtures/instance-config-policy-parity.toml). The 2026-10-21 U04a role-map checkpoint added a required closed `[workflow_roles]` map. It requires the five settled operation roles from repository capabilities, including `policy_check` whenever merge is enabled, and checks root-level workflow path syntax and duplicate claims. It does not authenticate files, source, pins or deployment identity, and it does not provide a loader. The complete schema and authenticated loading contract remain open.

Every trusted Server instance wrapper supplies the configuration-path input explicitly, relative to the **Server instance repository root**; there is no implicit documented-default path. Production reads bounded configuration bytes from that instance's protected main at a captured snapshot. Derive the instance repository from independently authenticated Server execution context; never let a Client choose the policy repository/path. Reject absolute/traversing/ambiguous paths and symlink indirection. Neither the reusable workflow distribution checkout, Client checkout nor PR's proposed configuration is production policy. Candidate configuration belongs only to an explicitly scoped scratch deployment.

Externalize account/repository/App identities, trusted actors/effective committers, capabilities, sensitive paths/exceptions, approval/merge/Securefix and Renovate authorization. Missing/invalid configuration stops execution; there is no civitaspo fallback. Configuration changes do not require a new Rust release. Keep production/test configuration and installation scopes separate.

`[acceptable_clients]` selects a trusted distribution repository and accepted stable release range, not a human-maintained SHA set. Accept `>=1.4.0` without an upper bound and optionally `>=1.4.0, <2.0.0`. This explicitly trusts future official releases from that publisher. Reuse the existing `semver` dependency and document its range syntax; see [VersionReq](https://docs.rs/semver/latest/semver/struct.VersionReq.html).

For every request independently establish the actual implementation repository/revision, its verified producer/source/asset provenance and official immutable release, version-in-range, actual pin-to-release correspondence, and supported request protocol. A self-reported version is insufficient. Check repository identity as well as name. Unsupported protocols reject even for a trusted future version. Stable production acceptance excludes SemVer prereleases, draft/unreleased sources and explicit scratch proofs; scratch-only exceptions must not be request-selectable production switches. SHA verification remains automatic; ordinary Client updates do not edit central SHA approval lists.

## Replace authority before removing the descriptor

| Existing descriptor responsibility | New authority |
| --- | --- |
| Select executable | Immutable workflow/action pin and release contract |
| Bind deployment policy | Protected-main TOML snapshot and configuration identity |
| Select accepted clients | Verified releases satisfying `[acceptable_clients]` and supported protocols |
| Reject superseded requests/approvals/writes | Configuration and Server deployment identities, replay protection and exact PR head |
| Authenticate executable/archive | Source/release/producer/asset/attestation verification |

ADR 0012 proposes `K`, `W`, and `E` for the replacement. The authenticated instance identity and exact TOML bytes form `K`. `W` covers only the strict `[workflow_roles]` map for ordinary CLI operations: each configured role's canonical thin wrapper bytes, its literal first-party pin, and the independently resolved package identity. Initial wrappers contain no local action, local reusable workflow, script, or client-controlled executable hook; there is no transitive local-dependency closure in `W`. Repo-settings reconciliation and the trusted package publisher have separate authority lifecycles and remain outside this ordinary-operation identity. Unreferenced OSS `workflow_call` source changes do not affect `W` while the mapped wrappers and their pins are unchanged. Do not hash all of main: unrelated Rust/docs changes must leave the deployed authority unchanged.

Before closing D03/D04/D05, a source-owned required-CI inventory test must classify every workflow matching the known ordinary Server installation-token minting or PR/protected-main write patterns. Every classified ordinary writer must be one of the configured canonical role wrappers; an unclassified ordinary writer fails CI. This is a closed check over known ordinary-operation patterns, not a workflow interpreter or a universal audit of every repository credential. Repo-settings and trusted publication remain separate lifecycles. The owner-selected source/check trust boundary in ADR 0012 is explicit; this design does not claim protection from its deliberate compromise.

The closed inventory must also explicitly classify the legacy distribution, control-activation, caller-migration, and bootstrap/repair writer lifecycles; the five ordinary roles do not cover them automatically. Before cutover, scratch must prove queued or in-flight old-controller writes and owner-dispatched legacy writer lanes are fenced or retired through a reviewed exact transition. An unchanged `control/active.json` alone does not establish that they have lost authority. Keep D03/D07/U08 open until this evidence exists; no transition mechanism or production disablement is selected here.

The target deployment identity follows the configured ordinary role map, not every OSS source file. A mapped wrapper's role, path, and bytes are bound; the initial wrapper must be thin and use no local `uses` dependency. This is separate from the currently deployed legacy dependency closure, whose local dependencies remain frozen until that caller migrates. Do not silently extend the target identity with local helpers; a wrapper that needs them reopens D03/D05.

Also solve change-and-revert replay: restoring identical configuration/pin bytes must not resurrect an old command. Proposed ADR 0012 defines `E` from the newest first-parent raw path change among the exact TOML and mapped role paths, found with one traversal over the complete commit/tree graph from exact `M` using a blob-filtered, no-depth fetch. It has no commit-count cap. Provisional resource bounds include a 64 MiB object-store cap, 30 seconds per network Git child, and 60 seconds total, plus bounded process output and current-blob reads. A cap breach, incomplete graph, shallow boundary, or timeout fails closed; a long sequence of small unrelated commits does not itself require an instance update. These bounds and the retrieval remain unqualified until parity, failure, and hosted scratch evidence is reviewed. Do not require a mirrored generation/version setting or claim an implemented guarantee.

Require all first-party operational Server pins in one instance to use one coherent release revision. This avoids supporting accidental mixtures of Server releases. Feature boundaries remain independently testable. Mixed Server releases require a later explicit compatibility design, not accidental pin skew. Keep third-party action pins separately verified/locked.

D03/D04/D05 remain open: the canonical ordinary-role inventory, full-history retrieval and resource-cap behavior, and coherent pin proof still require review and positive/rejection scratch evidence. The 64 MiB/60-second bounds are provisional. Preserve the existing owner-selected scratch threat model and test-only installation scopes; do not add a candidate CLI/container boundary, require another App, or request administrative privileges/settings reads.

Bind accepted ordinary-operation requests, owner commands/reviews, replay markers and each in-scope privileged write to exact target PR head plus configuration and deployment identities. Capture one configuration snapshot at start; before each ordinary write, independently reconstruct current authority and reject changes. Preserve expected-head CAS, signatures, required checks, operation-specific authorization, scopes and the serialized `securefix-control` lane. Repo-settings reconciliation and trusted publication retain their separate credentials and authority contracts. Do not add administration reads, credentials, bypass actors, direct Contents writes or native auto-merge. Do not claim GitHub provides an atomic cross-repository transaction.

An instance's own pin/configuration PR is authorized under the current authority and validates its complete proposed successor plus scratch evidence. Its merge is the terminal privileged action under that authority. Any subsequent write requires a new run/current authority; do not grant old commands a general post-cutover exception. Reverting a deployment creates a new authority epoch and requires fresh commands.

## Independent repo-settings reconciliation

Repo-settings owns required workflow files, literal implementation pins, permissions, triggers, inputs, call structure and instance configuration. A pin change is an explicit reviewed deployment change based on a qualified package; this plan does not add Renovate behavior or tests. Neither OSS release nor runtime publication triggers bulk workflow distribution.

Reconcile the exact canonical desired files and reject unsupported structure or protocol. Do not preserve or repair pins through generic version-selection logic, infer update obligations from age, a new release, an open PR, elapsed time or a failed run, or choose a target from partial release pagination. A pin or structure change is proposed as one signed managed-file PR against the captured default-branch head and is never auto-merged.

Use signed, reviewable, exact-file/expected-head PRs and existing canonical workflow/lockfile validators. No automatic merge. Reconciliation repeated on converged state produces no diff. Keep administrator settings reconciliation in its existing dedicated job/credential; the workflow-PR writer has only required repository-scoped privileges in a separate job, never inherited administrator credentials. Neither process becomes a new approval/merge authority.

## Staged delivery and migration

Every phase uses the detailed units in the execution guide. A failed gate stops its dependent phases; independent source work can continue without touching production. The initial freeze protects the currently working dependency closure, not only the executable: today's main-side workflows can still break it.

**Migration direction (2026-10-21).** A declared temporary downtime window is acceptable. Old Client coexistence is not a cutover requirement: do not build a descriptor-era runtime bridge, a predecessor/bridge/new Server × old/preparatory/new Client matrix, a preparatory Client, or permanent legacy-protocol acceptance solely to keep old callers working. The security gates remain: source and publisher proof, credential isolation, exact current-authority and head fences, fencing of accepted old writes, rejection of stale commands, and an owner-reviewed transition.

**First functional fast path.** Start with one `policy_check` request from a disposable Client PR to the new Server and require a result for the exact captured PR head. Run it in `testing-securefix-server` with a direct source-bound candidate artifact, before generic release publication or repo-settings reconciliation. The only initial gates are the affected candidate source/run/artifact binding, request protocol, a valid explicit config accepted by the existing strict parser with this route's policy fields set, repository/actor/capability identity, exact-head/current-write checks and scratch-only credential scopes. Exercise the positive path and a stale-head rejection; other routes and the full design remain later work. For uncertain GitHub behavior, use a small focused scratch probe and record its run and state instead of expanding this path into a broad matrix.

Direct edits to scratch workflows/configuration, disposable PRs/branches, and scratch repository settings may be used to wire the path and can be created, changed, deleted and recreated as needed. These changes use only test-repository authority; scratch administrator credentials stay outside ordinary candidate workflows. They do not require repo-settings to be implemented first. After the path passes, adopt its persistent workflow/config and any owned settings into repo-settings desired state and prove reconciliation converges to zero diff. Keep production workflows, configuration, settings, credentials, App permissions and current dependency closure untouched.

| Phase | Deliverables | Evidence required to proceed | Stop/return condition |
| --- | --- | --- | --- |
| P0 — inventory/freeze | U01 facts, live/source inventory, dependency closure, cost baseline, known-good deployment record | Full production dependency inventory before shared operational edits or cutover; the bounded scratch path may start after its own route and test scopes are captured | Unknown current authority or production closure: no shared production edit |
| P1 — settle affected design | Minimal U02 contract for the first slice; remaining field map, release, identity, protocol, reconcile and cutover decisions proceed before dependent units | Candidate source/artifact, selected request, a valid explicit config and its relevant policy fields, repository/actor/capability, exact head/current-write checks and test-only scopes are specified for the slice | An unproved affected trust/write gate stops that scratch route; unrelated design and source work continue |
| P2 — first new-stack vertical slice | U05a one `policy_check` request from a new Client through the new Server | Positive exact-head result and stale-head rejection pass in `testing-securefix-server` using the direct source-bound candidate artifact | Fix/revert only disposable scratch changes; current production closure stays frozen |
| P3 — deployment lifecycle | U06 adopts the verified workflow/config/settings into repo-settings and proves zero-diff reconcile | Managed structure converges in scratch after the direct slice is proven | Pause only affected reconcile work; keep current production closure frozen |
| P4 — qualify generic delivery and cutover | U03/U04/U05 full package, config, authority and feature proof; U08 generic publisher, exact transition, writer fencing, self-PR and conditional return | Required published feature paths and policy-free archive/publisher pass; reviewed exact-head route to coherent Server/TOML successor is proven | No qualified publisher or authorized/fenced cutover route: do not cut over |
| P5 — cut over Server | U09 coherent Server pins plus TOML under the existing reviewed lane or a separately reviewed bounded transition | Exact artifacts/config/head; old requests and commands reject; new Server and canary Client accept fresh authorized requests | Pause/resume only through the rehearsed transition; use a known-good return only when its prerequisites hold |
| P6 — optional Client rollout | U10 canary and any owner-approved cohorts, with reviewed structural deployment PRs | New Client paths pass for each cohort before expansion; unsupported callers are explicitly suspended or remain unsupported until updated | Stop later cohorts; use only a qualified per-Client return or forward fix |
| P7 — retire legacy | U11 retirement evidence and removal PRs | No active legacy readers, writers or callers; stale old commands reject; reviewed deployment and reconcile paths work | Any active dependency remains: retain only the needed bounded legacy path; do not delete the descriptor first |

### Cutover and transition constraints

The existing publisher/validator requires bundled policy and descriptor-era source bindings. It cannot be assumed to publish or activate a new generic archive. Qualify the generic OSS publisher against the policy-free archive, source/provenance contract and isolated credentials before deploying a Server pin. Any bounded publication adapter must be separately justified and reviewed; it is not a Client-compatibility bridge. Transitional legacy archives may still carry the unchanged legacy policy; keep them legacy-only and remove that path at its retirement gate. Final generic releases must not contain consumer policy.

Old Clients bind request source/runtime fields to active control. Do not relax those checks, translate old commands into new authority, or let a Client select a binary from `active.json`. The new Client may be rejected by the old Server, and old Clients may be rejected after the new authority takes effect. That temporary outage is allowed; no dual-acceptance mode, preparatory Client or full version matrix is required solely for continuity. First qualify one new Client + new Server `policy_check` vertical slice in scratch with direct source-bound artifacts, including its exact-head success and stale-head rejection. Broader route coverage remains a later pre-cutover gate.

The exact authorization path for the coherent Server pin/TOML transition remains a gate. In scratch, establish whether the existing reviewed lane can validate and merge that exact successor under current authority. If not, design a separately reviewed, narrowly scoped migration executor only if evidence shows it is necessary. Bind it to the full current authority, exact protected-main revision and PR head, expected-head CAS, allowed files, required checks, actor/signature policy, isolated credentials and serialized mutation lane. Do not revive bootstrap/repair, add an administration bypass, or assume an ordinary old-Server merge can accept descriptor removal or a generic archive.

Cutover must stop admission to old request/writer lanes and reject old commands while fencing queued or in-flight writes already accepted under old authority. Merely disabling triggers does not revoke those writes: the actual write must recheck the current full authority and exact head. Apply the coherent Server pin/TOML successor through the qualified current lane or bounded executor, activate a new Client canary, and resume only fresh commands after the new stack passes. An optional pre-update of Client pins under the current Server may reduce downtime only if the exact legacy validator and migration rules pass scratch review; it is not required and is not an assumed compatibility path.

During development preserve current production handlers, their local dependencies, active runtime and caller pins. Add new implementation under separate non-operational paths and explicit scratch wiring. Do not add parallel production mutation listeners. Before merging a shared production dependency edit, prove it works with the exact active runtime in scratch or keep it out of the current operational closure.

### Availability and recovery acceptance

Before cutover, test every affected new Server + new Client route for PR creation, approval, merge, Securefix and release, plus the Server's own source-only and pin/configuration update PRs. This broader matrix is a cutover gate, not a prerequisite for the first `policy_check` slice. Source inspection found an ordinary route for owner-authored Server source PRs: the owner `/approve` command, a distinct configured bot review, then a separate owner `/merge` subject to checks and expected-head CAS. The `/approve` command is request authorization, not a native GitHub review; the source requires `reviewDecision=APPROVED` and the configured bot review, but does not establish a general requirement for an additional owner-authored native review. This route does not handle descriptor transitions, which use a separate activation contract. See the [U08 source-PR route and evidence boundary](development-loop-execution-guide.md#owner-authored-source-pr-route). This is source-level evidence, not live certification; U08 must still rehearse the exact route in scratch and record its current requirements. A source-only main merge must not change new deployment identity. A pin/configuration change must invalidate old authorization; fresh authorization must work. Configuration or deployment changes followed by reverts must not revive requests. At cutover, old Client commands reject; the plan does not require old/new Client service continuity.

A fixed healthy Server allows fixes to unactivated implementation source. It does not guarantee that a broken deployed Server can process its own repair. Before cutover, enumerate and rehearse the exact known-good return path, credentials, owner action, branch/ruleset restrictions, supported new Client versions and circumstances in which the path is unavailable. Ordinary rollback is a reviewed known-good pin/configuration PR only when the running lane can still process it. If total lane failure needs separate recovery, obtain a reviewed design and evidence for that path or declare it unavailable and block any promised recovery guarantee. Never expand privileges or use production merges as experiments.

The U08 self-PR checkpoint requires two separate scratch rehearsals before cutover: a source-only Server self-PR that leaves the deployed literal pins on the same binary, and a coherent Server pin/config self-PR validated under the current authority. The pin/config merge is the old authority's final privileged write. Prove that a follow-on old-authority command is rejected and a fresh successor-authority run succeeds; record exact PR heads, actor/signature/effective-committer evidence, review and required checks, independent resulting state, and the tested return route with its availability conditions. A fixture PR or local test alone does not pass. If the supported code-repair route or a promised return path cannot be demonstrated, keep the gate open and do not cut over.

Keep a bounded legacy-retirement register for remaining readers, writers, callers and their removal conditions. At cutover, reject old-authority commands and revoke pending work; do not retain legacy protocol success paths merely to serve every old version. Remove legacy loaders, descriptor handling, bundled policy, publication and distribution only after no active legacy reader, writer or caller remains and rejection tests prove stale commands cannot mutate state. Unsupported callers may be suspended until updated or explicitly retired.

## Completion and evidence

| Scenario | Required result |
| --- | --- |
| Rust/docs source merge or OSS release without instance pin change | Running Server implementation and authority unchanged |
| Fixed old Client/Server pin after other releases/configuration changes | Same corresponding binary; policy changes can revoke authority, never select a different binary |
| Stable future Client release in configured unbounded range | Accepted with valid provenance/revision and supported protocol; no central SHA-list edit |
| Self-reported version, wrong publisher/revision/asset, prerelease, unknown protocol | Rejected before privileged mutation |
| Missing/substituted/untrusted configuration | Rejected; no fallback policy |
| Config/deployment changes, exact revert, PR-head change or replay | Old request/command/receipt rejected; fresh authorization required |
| Unclassified ordinary Server token-minting or PR/protected-main writer pattern | Required CI rejects it unless it is one of the configured canonical wrappers; this closed check does not audit every repository credential or replace separate repo-settings/publisher lifecycles |
| Source-only Server self-PR and coherent Server update self-PR | Both handled under their correct pre-merge authority; no follow-on stale write |
| Partial/mixed Server pin update | Rejected by CI and runtime deployment qualification |
| New Client canary failure | Keep fresh request processing paused; apply only a separately qualified fix or return path, and report when neither is available. Do not claim automatic whole-lane recovery. |
| Known-good Server return | Rehearsed with explicit availability conditions, never presumed universal |
| Final cleanup | No active descriptor reader, legacy writer/caller, consumer policy archive/embedding, or release-triggered distribution remains; focused stale-command rejection tests remain |

Record sources, actual workflow/action revisions, configuration/deployment identities, protocol/release proofs, producer run/attempt, artifact/asset IDs/digests, exact PR heads/reviews/checks, independent resulting state and cleanup. Preserve failed attempts and distinguish code inspection, direct scratch, published scratch and authorized production observations. Do not invent timing/token measurements.

Measure edit-to-first-useful-result, builds, fixtures, hosted waits, publication/deployment count and update PRs against P0. Direct immutable candidate artifacts are the inner loop; release only when qualifying delivery, not after every edit. Reuse existing Rust helpers, the existing scratch repository and pinned tooling. Run relevant tests first and standard repository checks once per assembled implementation change; documentation-only work requires accuracy/link checks and required CI, not Rust test reruns.

Read the current [overview](../README.md), [domain contract](../CONTEXT.md), [merging](merging.md), [client action](client-action.md), [client releases](client-releases.md), [settings](repo-settings.md), [migration](migration.md), [testing](testing.md), [integration testing](integration-testing.md) and [lockfile contract](workflow-lockfiles.md) before changing their flows. Update these and repository agent instructions when implementation changes the contracts; preserve historical deployment reports as dated evidence.
