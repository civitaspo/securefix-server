# Accept exactly the current server runtime

Client workflows pin a full server commit SHA.
The server accepts only the current protected `main` revision, including the Rust executable.
An older revision being an ancestor of `main` does not make it acceptable.
This avoids a compatibility window in which old authorization code remains usable.

The [GitHub job context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) exposes `job.workflow_sha` for the workflow that defines a reusable job.
We use it to check out the server source and compile without custom secrets.
Privileged jobs download the resulting immutable artifact ID.
The source SHA travels with the runtime and is checked against current policy before privileged effects.

Every server commit requires clients to update their pins before making another request.
This includes changes unrelated to a particular reusable file because its executable and policy are part of the same trust unit.
Policy changes do not instantly revoke a previously successful required check on an unchanged PR head.
An emergency stop remains a manual operation.
