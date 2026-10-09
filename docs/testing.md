# Candidate integration tests

Use `Test Candidate Runtime` on the server's trusted main workflow with a full reviewed candidate SHA. The candidate does not need a merged production revision or a Runtime Release.

```sh
gh workflow run testing-securefix-server.yml --repo civitaspo/securefix-server --ref main -f candidate_sha="$CANDIDATE_SHA" -f phase=prepare
```

The prepare job builds and tests without credentials. Its execution job receives only Server and Client App installation tokens restricted to `civitaspo/testing-securefix-server`. The repository ID and token installation scope are checked in Rust before creating fixtures. No personal approval token, administration token or release signing key is passed to the candidate.

The prepare run records three scratch PRs in `scratch-fixtures/state.json`. An authenticated owner controller posts `/approve` and `/merge` to the positive PR, posts `/merge` to the stale-head PR, and approves the positive PR's current commit. These commands can be posted by the coding agent using its existing owner GitHub session. The test does not require the human to post them.

```sh
gh workflow run testing-securefix-server.yml --repo civitaspo/securefix-server --ref main -f candidate_sha="$CANDIDATE_SHA" -f phase=verify -f fixture_run_id="$PREPARE_RUN_ID"
```

Verification reuses the prepare run's candidate binary. Before minting write credentials it checks the successful owner-triggered producer run, the defining workflow revision, the candidate SHA and the bounded immutable state artifact. It verifies actual signatures, owner authorization, current-head approval, required checks, signed workflow migration files, a successful squash merge, stale-head rejection and replay rejection. Remaining PRs and branches are cleaned up.

The scratch main branch requires a non-author approving review, signed commits, `status-check` from GitHub Actions and `securefix-policy-check` from the Server App. A policy success is published only after the shared production PR validator accepts the current head.

See [the harness contract](integration-testing.md) for the boundary between live functional tests and source-provenance fixtures. Stable runtime publication is a separate protected-main operation after candidate verification and review.
