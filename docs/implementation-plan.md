# Rust migration

The implementation replaces repository-owned shell, Ruby, Python, and github-script business logic with one Rust package. It contains the normal `securefix` executable and the separately built, source-pinned `securefix-bootstrap` executable for initial activation.
Workflows retain event routing, permissions, environments, isolated jobs, pinned actions, and calls to the executable.

- [x] Frame the trust boundaries and operation capabilities.
- [x] Compare designs and settle the approval, merge, release, and settings contracts.
- [x] Build the common API boundary, policy model, and immutable CLI artifact transport.
- [x] Replace each operation and verify its rejection cases.
- [x] Review the integrated workflows independently and run the full local checks.
- [x] Replace per-operation Rust builds with attested SemVer Releases bound to the exact source SHA and verify the hosted loader boundary.
- [x] Deploy to GitHub and verify real App permissions, approval/merge, release publication, and settings lifecycle behavior.
- [x] Verify automatic caller distribution and remove temporary deployment allowances and fixtures.

Local completion means the CLI builds with locked dependencies, formatting and Clippy pass, workflow validation passes, and regression tests exercise authorization decisions through typed input or HTTP fixtures.
Deployment and lifecycle verification are also complete. The native Rust runtime is active on protected main and distributed to the configured callers.
See the [deployment verification](deployment-verification-2026-10-11.md) for dated evidence, including the normal merged release-PR path and Terraform Registry registration.
The [initial GitHub verification report](github-verification-2026-10-08.md) describes pre-deployment API probes and remains historical evidence.

The implementation was delivered across three disjoint workstreams.
Approval and merge share request provenance and owner authorization.
Release owns packaging, signing, and publication.
Settings owns reconciliation, activation, and the Securefix adapter.
The coordinator owns policy, runtime transport, the independent head check, documentation, and integrated verification.
