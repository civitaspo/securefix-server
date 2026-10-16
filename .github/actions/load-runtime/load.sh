#!/usr/bin/env bash
set -euo pipefail
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'source-sha must be a full lowercase commit SHA' >&2; exit 1; }
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'repository must be owner/name' >&2; exit 1; }
[[ "$DEFAULT_BRANCH" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || { echo 'default-branch is invalid' >&2; exit 1; }
candidates="$(mktemp "$RUNNER_TEMP/runtime-locators.XXXXXX")"
archive="$(mktemp "$RUNNER_TEMP/runtime-archive.XXXXXX")"
trap 'rm -f "$candidates" "$archive"' EXIT
for page in $(seq 1 10); do
  response="$(gh api "repos/$REPOSITORY/releases?per_page=100&page=$page")"
  jq -r --arg sha "$SOURCE_SHA" '
    .[] | select(.target_commitish == $sha) |
    .assets[]? | select(.name == "securefix-runtime-linux-x86_64.tar.gz") | .id
  ' <<<"$response" >> "$candidates"
  [[ "$(wc -c < "$candidates" | tr -d '[:space:]')" -le 1024 ]] || { echo 'runtime locator set exceeds size limit' >&2; exit 1; }
  if [[ "$(jq 'length' <<<"$response")" -lt 100 ]]; then break; fi
done
asset_id="$(cat "$candidates")"
[[ "$asset_id" =~ ^[1-9][0-9]{0,19}$ ]] || { echo 'runtime archive locator is missing, ambiguous, or malformed' >&2; exit 1; }
gh api "repos/$REPOSITORY/releases/assets/$asset_id" -H 'Accept: application/octet-stream' > "$archive"
actual_size="$(stat -c %s "$archive")"
[[ "$actual_size" -gt 0 && "$actual_size" -le 134217728 ]] || { echo 'runtime archive exceeds size limit' >&2; exit 1; }
gh attestation verify "$archive" --repo "$REPOSITORY" --source-digest "$SOURCE_SHA" --source-ref "refs/heads/$DEFAULT_BRANCH" --signer-workflow "$REPOSITORY/.github/workflows/publish-runtime.yml" --signer-digest "$SOURCE_SHA" --cert-oidc-issuer https://token.actions.githubusercontent.com --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners
runtime_dir="$(mktemp -d "$RUNNER_TEMP/securefix-runtime.XXXXXX")"
tar -xzf "$archive" -C "$runtime_dir" --no-same-owner
"$runtime_dir/securefix" runtime verify --source-sha "$SOURCE_SHA" --repository "$REPOSITORY" --archive "$archive"
echo "directory=$runtime_dir" >> "$GITHUB_OUTPUT"
