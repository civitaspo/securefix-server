# Verify a candidate on the scratch repository

Use [testing-securefix-server](https://github.com/civitaspo/testing-securefix-server) to check a reviewed server revision before publishing its production runtime.
The scratch `verify-server.yml` wrapper pins the server's reusable [testing workflow](../.github/workflows/testing-securefix-server.yml) to one full commit SHA.
Review the revision and update that wrapper pin before testing a new candidate.

Dispatch the wrapper on scratch main:

```sh
gh workflow run verify-server.yml --repo civitaspo/testing-securefix-server --ref main
```

Inspect the resulting run in the scratch repository's Actions tab.
Only the owner can execute the test workflow, and only from scratch main.
It builds the server at the reusable job's actual source SHA without custom secrets, runs Rust tests, and uploads the runtime and API probe as one immutable artifact.
The next job downloads that same-run artifact ID and installs the CLI through the same composite action used by production jobs.
It checks command discovery through `PATH`, executable mode `755`, policy acceptance and rejection, and the repository-scoped Client App metadata token.
The existing `SECUREFIX_CLIENT_PRIVATE_KEY` is used only by the token action; the probe receives the short-lived metadata-read token.
The run creates no Release and needs no cross-repository artifact token or additional secret.

Use the server PR's CI for formatting, Clippy, actionlint, and structural workflow checks.
The [verification record](github-verification-2026-10-08.md) distinguishes those checks from live GitHub API coverage.
The scratch CI does not exercise production approval, merge, signing, publication, or settings activation.
Follow the [deployment sequence](migration.md) for those privileged lifecycle checks; production commands retain their exact-current-main guard.

Once staging and review succeed, manually dispatch `Publish Runtime` on the server's current main revision.
Publishing intermediate commits is unnecessary.
Successful publication initiates caller update PRs and the server's default-head Policy Check.
Inspect the distribution run, its Securefix receiver runs, and the signed caller PRs before merging caller changes under the [maintenance procedure](migration.md#subsequent-server-upgrades).
To recover a failed distribution, dispatch a new `Distribute Runtime` run on server main with the successful publisher run ID.
An existing update PR is reused, and a caller whose default branch already has the generated workflows needs no PR.
After main advances, old client pins and runtimes stop working until the stable current revision is published and caller updates are merged.
The Server App private key remains in the server main environment.
That environment permits only main deployments, so candidate scratch CI cannot exercise its production write path before merge.
