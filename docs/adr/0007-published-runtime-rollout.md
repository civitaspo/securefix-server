# Distribute a published runtime through reviewed caller PRs

The server accepts only its current main revision for privileged operations.
Publishing that revision and updating callers are therefore one deployment sequence.
The original sequence left every caller update to the operator and ran the server's default-head Policy Check before its runtime existed.
The merge push for `7819d4abb70af791715492ec21b20563df4815df` failed with `release not found` in [run 37807897094](https://github.com/civitaspo/securefix-server/actions/runs/37807897094).
The later [successful publication](https://github.com/civitaspo/securefix-server/actions/runs/37862083255) could not refresh that check.

After a successful `Publish Runtime`, two workflows use the verified Release for that same current-main SHA.
Policy Check captures the server's current default head and sends the existing App-bound policy request.
Distribute Runtime prepares caller workflow changes and sends one Securefix request for each configured caller.
Failed publication and stale publication events authorize neither operation.

`policy.json` defines the exact caller set, excluding the server itself.
The Securefix configuration permits the server's protected main source to write only those repositories' `automation/securefix-runtime` branch.
Rust treats this as a separate promotion source and checks the publisher, current runtime, destination, branch, and exact generated workflow files.
The existing client PR and release-PR source rules remain separate.
Downloaded caller files never supply executable code for the distribution job.

Securefix Action retains artifact transport, preparation, signed commits, and token cleanup.
Its commit phase creates a new PR whenever PR metadata is present, even if a PR already exists.
Distribution therefore omits upstream PR metadata and uses Rust to find or create the one update PR for the fixed branch.
An identical retry reuses that PR; a later promoted SHA updates the same branch.
Unexpected branch ownership or files stop the update for review.
The updater never merges its PRs or changes branch protection.
If the caller's default branch already has the generated files, distribution makes no request or PR.
Concurrent requests can fail safely at the upstream commit or GitHub PR creation boundary.
A fresh owner-dispatched `Distribute Runtime` run can recover a failed distribution using its successful publisher run ID.
Rerunning a receiver is insufficient because privileged requests require the first attempt of a new run.

The first distribution includes the caller contract migration, such as the policy-check wrapper, attestation-read permissions, head-bound approval requests, and release retry input.
These changes remain reviewable in the caller PR.
The subsequent server-upgrade maintenance procedure still applies because PR-target workflows read wrappers from the caller's default branch.
Creating a pin-update PR cannot itself switch the wrapper used to check that PR.

We considered Renovate and a separate Rust commit engine.
The SHA-keyed runtime tags do not provide an ordered version stream for native Renovate updates, and digest updates alone cannot add the missing caller contracts.
A custom commit engine would duplicate Securefix's supported transport and signed-commit behavior.
The selected design adds only promotion authorization, caller generation, and PR reuse.

Securefix still chooses the destination head internally when committing.
This design does not introduce an expected-head guarantee absent from the upstream action.
The accepted upstream limitation is recorded in [ADR 0005](0005-upstream-securefix-protocol.md).
The generated changes are confined to reviewed workflow files on a review branch.

The scratch CI verifies candidate code without publishing intermediate Releases.
Live Server App writes require the server's main environment, whose deployment branch policy allows only main.
Pre-merge scratch results do not certify production distribution, App permissions across the caller set, or the post-publication App-bound check.
Those results must be checked after the reviewed revision is merged and promoted.
