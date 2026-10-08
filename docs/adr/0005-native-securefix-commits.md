# Bind Securefix commits to their validated inputs

The pinned upstream commit action fetches the destination branch head at write time.
It cannot enforce the source head accepted by the server, and its prepare action downloads artifacts by name without exposing the chosen artifact ID.
Keeping those server actions would leave write scope split between Rust validation and another implementation.

The native Rust server consumes the existing client artifact format from its exact immutable ID.
It rejects unlisted payloads, unsafe paths, git metadata, symlinks, and oversized entries.
It reads validated bytes directly instead of extracting client files into a privileged job's workspace.

CI fixes target the source branch at the source run's exact head.
Release-PR preparation captures the current release branch head or creates the absent branch from its validated default-branch source.
GitHub's [createCommitOnBranch](https://docs.github.com/en/graphql/reference/commits#createcommitonbranch) applies additions and deletions with an `expectedHeadOid` precondition and signs supported commits as the authenticated identity.
The server checks the returned signature, parent, and updated reference.
Concurrent head changes fail closed and require a fresh request.

Creating an absent release branch and checking its default-branch source are separate API operations.
A concurrent default-branch update can leave the new branch based on the older validated run; retry from a fresh run if that occurs.
The commit still requires the captured destination head, and GitHub cannot atomically guard both refs.
