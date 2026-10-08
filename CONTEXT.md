# Glossary

| Term | Definition |
| --- | --- |
| Client | A civitaspo repository that requests an allowed operation from this repository. |
| Server | This repository, which holds credentials for privileged OSS operations. |
| Capability | Permission for one named operation on one exact repository. |
| Request locator | The client repository and workflow run ID carried in a server label. |
| Request manifest | The immutable record of a request and its captured repository, source, and target identities. |
| Accepted head | The PR head SHA observed when an owner command is captured. |
| Owner authorization | An owner command accepted for one exact PR head. |
| Sensitive change | A change to a path whose automatic approval requires owner authorization. |
| Runtime revision | The server commit containing the CLI and the workflow that calls it. |
| Release identity | The repository, merged release PR, commit, tag, and version being published. |
| Release bundle | The unsigned, canonical publication assets produced by the isolated build job. |
| Activation | Creating or reactivating the controlled-merges ruleset after checking the full configured repository set. |
| Reconciliation | Applying configured settings to an existing repository or active ruleset. |
