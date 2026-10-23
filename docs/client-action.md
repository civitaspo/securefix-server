# Securefix client action

The composite action at `.github/actions/client` installs the Rust runtime, stages and uploads the selected workspace files, then asks the runtime to create the server request label. It does not compile the CLI or bypass the Rust client's bounded label-write path.

The caller must grant `actions: read`, `contents: read`, and `attestations: read` to validate the descriptor-selected publisher run, download the runtime release, and verify its attestation. For a private runtime repository, pass a read-only `runtime-token` with those permissions; it must be scoped to the runtime repository. For a public runtime repository, the default workflow token may provide these reads. These credentials cannot write production state. Pass a short-lived GitHub App installation token restricted to the configured server repository and `issues: write` as `client-token`. That token is used only by `client-dispatch`; do not pass an App private key to the action.

```yaml
permissions:
  actions: read
  contents: read
  attestations: read

steps:
  - uses: actions/checkout@<full-commit-sha>
  - uses: example-org/securefix-server/.github/actions/client@<full-commit-sha>
    with:
      runtime-sha: <full-runtime-commit-sha>
      server-repository: example-org/securefix-server
      runtime-default-branch: main
      client-token: ${{ secrets.SERVER_REQUEST_TOKEN }}
      files: |
        CHANGELOG.md
        package.json
      branch: automation/release
      commit-message: Prepare the release
```

`runtime-sha`, when supplied on the published-release path, must equal the active runtime source SHA. The loader resolves the configured server default branch, reads `control/active.json` at that branch head, validates the successful owner-dispatched publisher run named there, and uses its `release_id` and `asset_id` to select the immutable published release and the `securefix-runtime-linux-x86_64.tar.gz` asset. It selects an attestation signer only from the fixed trusted workflow paths (`publish-runtime.yml`, or `control-bootstrap.yml` for the initial archive when a later rollback descriptor selects that same archive), checks the descriptor's source, generation, policy digest, and archive digest, verifies the asset bytes and GitHub attestation, and installs the runtime with the descriptor as `control.json`. The runtime validates the descriptor and exposes its identity as the `runtime-control-id` action output. The descriptor pins the runtime independently of later ordinary source commits. `load-cli.yml` uses the same `.github/actions/load-runtime/load.sh` bootstrap through the `load-runtime` composite wrapper. `runtime-repository` defaults to `server-repository`; use it to run an upstream runtime against a separately configured server deployment. The archive supplies both `securefix` and its adjacent `policy.json`.

The action's `files` input is newline-separated and relative to `root-dir` (default `.`). `repository` may select the destination repository; `branch` and `commit-message` are optional. To request a pull request, provide `pull-request-title` and `pull-request-base`, with optional `pull-request-body`. `custom-json` must be a JSON object. The action exposes `artifact-name`, `source-label`, `changed-files`, and `runtime-control-id` outputs; when `files` is empty, it skips upload and dispatch.

`policy-path` can point to a workspace-relative, trusted deployment policy for the Rust runtime. Use only a file selected by a trusted workflow or checked-in controller configuration; never derive this input from a PR or artifact. If omitted, the policy shipped beside the runtime is used. The action checks that the selected path resolves to a file within the workspace.

`runtime-directory` is for isolated candidate tests. In this mode, `runtime-sha` must be the candidate source SHA bound by the host's validation. Before minting a token, the trusted host validates its defining workflow with `securefix integration validate-producer`. It downloads the immutable artifact ID emitted by the successful, credential-free build job for the exact candidate SHA. For reuse across runs, `securefix integration fetch-state` also validates the successful producer run and artifact ID. Mint only scratch-repository tokens. Pass the validated artifact directory containing `securefix` and `policy.json`; the action rejects symlinks and files outside the workspace. This mode skips descriptor and release-attestation loading inside the action because the trusted host performed the producer check. Candidate-artifact smoke tests therefore do not verify the published loader. Live verification of the published-release path requires the initial active descriptor and remains pending until that bootstrap exists.

Pin both the action and runtime to full commit SHAs. The caller is responsible for obtaining `client-token` from an installation limited to the server repository; the action does not mint or broaden that token.

For the supported managed autofix layout, runtime distribution also migrates
`wc-autofix.yml`, `workflow_call_pr.yml`, and `pull_request.yml`. It preserves
the existing formatter, check and configuration steps, replaces the legacy
client step with this action and a narrowly scoped token step, and adds
`actions: read` and `attestations: read` to the three managed jobs. The loader
uses `actions: read` to inspect the descriptor-selected publisher run, then
downloads its release asset and verifies its attestation. A prior generated
layout with attestation access but without `actions: read` is upgraded on the
next distribution. Subsequent promotions update the action and runtime pins
together. Server identities and App IDs come from the trusted deployment
configuration. Unsupported action inputs, ambiguous step layouts and write
permissions stop the migration.

Distribution also adds a positive `status-check` aggregator to the supported
default-branch push CI. For the minimal CI layout it adds default-branch push
and manual triggers. The aggregator fails when its dependency fails, is
cancelled, or is skipped. This lets activation verify real checks on the exact
new default-branch commit rather than relying on pre-merge PR checks.

The generated Merge Request wrapper permits the configured owner and the exact configured Renovate Bot on its own PRs. The runtime records bot requests separately from owner authorization and revalidates their provenance and accepted head. See [Renovate requests](merging.md#renovate-requests); changing a wrapper alone cannot authorize a bot in an older active runtime.

## Fixed package loader

Server and Client jobs use the same `load-package` composite Action pinned to a
full commit SHA. Its only required input is `token`, normally `${{ github.token }}`,
used for read-only package and provenance requests. Its bundled schema-v3
`package.json` selects one immutable release, asset, source revision, source
manifest digest, and producer/publisher run pair. The source build specification
is a separate `source-package.json`; it does not select a published binary.
Workflow, Action, and binary source revisions may differ. Multiple jobs may use
the same fixed mapping without sharing their operation credentials.

The Node.js 24 TypeScript loader validates the Linux x86-64 platform, repository
identities, source specification, release state, size, digest, run identities,
and cryptographically verified source/workflow-bound provenance before making
the binary executable or adding its directory to PATH. It never executes the
unverified binary. A relocated copy of the Action resolves its own manifest and
modules relative to its files. Caller repository, actor, event, and attempt do
not grant or deny package loading. Rust and the operation workflows retain
request admission, policy, credential isolation, signatures, expected-head and
stale authority checks. Download permission does not authorize a mutation.

The current development mapping explicitly selects the verified scratch
prerelease `v0.2.45-pre.42` in `civitaspo/testing-securefix-server`. It does not
change the production `load-cli` or `load-runtime` path or activate a runtime.
