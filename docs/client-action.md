# Securefix client action

The composite action at `.github/actions/client` installs the Rust runtime, stages and uploads the selected workspace files, then asks the runtime to create the server request label. It does not compile the CLI or bypass the Rust client's bounded label-write path.

The caller must grant `contents: read` and `attestations: read` to download and verify the runtime release. For a private runtime repository, pass a read-only `runtime-token` with those permissions. Pass a short-lived GitHub App installation token restricted to the configured server repository and `issues: write` as `client-token`. That token is used only by `client-dispatch`; do not pass an App private key to the action.

```yaml
permissions:
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

`runtime-sha` identifies the exact `securefix-runtime-<sha>` release. `runtime-repository` defaults to `server-repository`; use it to run an upstream runtime against a separately configured server deployment. The action verifies the archive attestation against the runtime repository, `runtime-default-branch`, `publish-runtime.yml` signer, and the same source and signer SHA before extracting it. The archive supplies both `securefix` and its adjacent `policy.json`.

The action's `files` input is newline-separated and relative to `root-dir` (default `.`). `repository` may select the destination repository; `branch` and `commit-message` are optional. To request a pull request, provide `pull-request-title` and `pull-request-base`, with optional `pull-request-body`. `custom-json` must be a JSON object. The action exposes `artifact-name`, `source-label`, and `changed-files` outputs; when `files` is empty, it skips upload and dispatch.

`policy-path` can point to a workspace-relative, trusted deployment policy for the Rust runtime. Use only a file selected by a trusted workflow or checked-in controller configuration; never derive this input from a PR or artifact. If omitted, the policy shipped beside the runtime is used. The action checks that the selected path resolves to a file within the workspace.

`runtime-directory` is for isolated candidate tests. In this mode, `runtime-sha` must be the candidate source SHA bound by the host's validation. Before minting a token, the trusted host validates its defining workflow with `securefix integration validate-producer`. It downloads the immutable artifact ID emitted by the successful, credential-free build job for the exact candidate SHA. For reuse across runs, `securefix integration fetch-state` also validates the successful producer run and artifact ID. Mint only scratch-repository tokens. Pass the validated artifact directory containing `securefix` and `policy.json`; the action rejects symlinks and files outside the workspace. This mode skips release-attestation verification inside the action because the trusted host performed the producer check. Keep production calls on the default attested-release path.

Pin both the action and runtime to full commit SHAs. The caller is responsible for obtaining `client-token` from an installation limited to the server repository; the action does not mint or broaden that token.

For the supported managed autofix layout, runtime distribution also migrates
`wc-autofix.yml`, `workflow_call_pr.yml`, and `pull_request.yml`. It preserves
the existing formatter, check and configuration steps, replaces the legacy
client step with this action and a narrowly scoped token step, and adds
`attestations: read` throughout the reusable-workflow call chain. Subsequent
promotions update the action and runtime pins together. Server identities and
App IDs come from the trusted deployment configuration. Unsupported action
inputs, ambiguous step layouts and write permissions stop the migration.

Distribution also adds a positive `status-check` aggregator to the supported
default-branch push CI. For the minimal CI layout it adds default-branch push
and manual triggers. The aggregator fails when its dependency fails, is
cancelled, or is skipped. This lets activation verify real checks on the exact
new default-branch commit rather than relying on pre-merge PR checks.
