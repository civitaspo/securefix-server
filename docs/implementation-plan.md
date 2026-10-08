# Rust migration

The implementation replaces repository-owned shell, Ruby, Python, and github-script business logic with one Rust executable.
Workflows retain event routing, permissions, environments, isolated jobs, pinned actions, and calls to the executable.

- [x] Frame the trust boundaries and operation capabilities.
- [x] Compare designs and settle the approval, merge, release, and settings contracts.
- [x] Build the common API boundary, policy model, and immutable CLI artifact transport.
- [x] Replace each operation and verify its rejection cases.
- [x] Review the integrated workflows independently and run the full local checks.
- [x] Replace per-operation Rust builds with attested SHA-keyed Releases and verify the hosted loader boundary.
- [ ] Deploy to GitHub and verify real App permissions and lifecycle behavior before activation.

Local completion means the CLI builds with locked dependencies, formatting and Clippy pass, workflow validation passes, and regression tests exercise authorization decisions through typed input or HTTP fixtures.
Deployment is a separate operation.
The migration PR is not deployed, and production settings, tags, releases, and merges are unchanged.
The existing default-branch approval workflow automatically reviewed the migration PR.
Live API fixtures and App credential probes are recorded in the [GitHub verification report](github-verification-2026-10-08.md).

The implementation runs across three disjoint workstreams.
Approval and merge share request provenance and owner authorization.
Release owns packaging, signing, and publication.
Settings owns reconciliation, activation, and the Securefix adapter.
The coordinator owns policy, runtime transport, the independent head check, documentation, and integrated verification.
