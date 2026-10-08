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
After main advances, old client pins and runtimes stop working until the stable current revision is published and pins are updated.
