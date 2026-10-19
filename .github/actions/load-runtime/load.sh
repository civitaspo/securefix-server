#!/usr/bin/env bash
set -euo pipefail
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'repository must be owner/name' >&2; exit 1; }
[[ "$DEFAULT_BRANCH" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || { echo 'default-branch is invalid' >&2; exit 1; }
WORKFLOW_PREFIX="${WORKFLOW_PREFIX:-}"
[[ "$WORKFLOW_PREFIX" == '' || "$WORKFLOW_PREFIX" == testing- ]] || { echo 'workflow-prefix is invalid' >&2; exit 1; }

descriptor="$(mktemp "$RUNNER_TEMP/control-descriptor.XXXXXX")"
archive="$(mktemp "$RUNNER_TEMP/runtime-archive.XXXXXX")"
trap 'rm -f "$descriptor" "$archive"' EXIT

repo="$(gh api "repos/$REPOSITORY")"
[[ "$(jq -r '.default_branch' <<<"$repo")" == "$DEFAULT_BRANCH" ]] || { echo 'server default branch differs from configured branch' >&2; exit 1; }
main_sha="$(gh api "repos/$REPOSITORY/commits/$DEFAULT_BRANCH" --jq '.sha')"
[[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'resolved main revision is invalid' >&2; exit 1; }
descriptor_response="$(gh api "repos/$REPOSITORY/contents/control/active.json?ref=$main_sha")"
[[ "$(jq -r '.encoding' <<<"$descriptor_response")" == 'base64' ]] || { echo 'control descriptor encoding is invalid' >&2; exit 1; }
jq -r '.content' <<<"$descriptor_response" | base64 --decode > "$descriptor"
[[ -s "$descriptor" && "$(stat -c %s "$descriptor")" -le 16384 ]] || { echo 'control descriptor is missing or exceeds size limit' >&2; exit 1; }

source_sha="$(jq -er '.source_sha' "$descriptor")"
generation="$(jq -er '.generation' "$descriptor")"
asset_id="$(jq -er '.asset_id' "$descriptor")"
release_id="$(jq -er '.release_id' "$descriptor")"
publisher_run_id="$(jq -er '.publisher_run_id' "$descriptor")"
expected_archive_sha="$(jq -er '.archive_sha256' "$descriptor")"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'active runtime source SHA is invalid' >&2; exit 1; }
[[ "$generation" =~ ^[1-9][0-9]*$ && "$publisher_run_id" =~ ^[1-9][0-9]{0,19}$ ]] || { echo 'active runtime generation or publisher run ID is invalid' >&2; exit 1; }
if [[ -n "${SOURCE_SHA:-}" ]]; then
  [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'source-sha must be a full lowercase commit SHA' >&2; exit 1; }
  [[ "$SOURCE_SHA" == "$source_sha" ]] || { echo 'requested runtime source SHA differs from the active descriptor' >&2; exit 1; }
fi
[[ "$asset_id" =~ ^[1-9][0-9]{0,19}$ && "$release_id" =~ ^[1-9][0-9]{0,19}$ ]] || { echo 'active runtime release or asset ID is invalid' >&2; exit 1; }
[[ "$expected_archive_sha" =~ ^[0-9a-f]{64}$ ]] || { echo 'active runtime archive digest is invalid' >&2; exit 1; }

publisher_run="$(gh api "repos/$REPOSITORY/actions/runs/$publisher_run_id")"
repository_id="$(jq -er '.id' <<<"$repo")"
[[ "$(jq -r '.id' <<<"$publisher_run")" == "$publisher_run_id" \
  && "$(jq -r '.status' <<<"$publisher_run")" == 'completed' \
  && "$(jq -r '.conclusion' <<<"$publisher_run")" == 'success' \
  && "$(jq -r '.event' <<<"$publisher_run")" == 'workflow_dispatch' \
  && "$(jq -r '.head_branch' <<<"$publisher_run")" == "$DEFAULT_BRANCH" \
  && "$(jq -r '.head_sha' <<<"$publisher_run")" == "$source_sha" \
  && "$(jq -r '.repository.id' <<<"$publisher_run")" == "$repository_id" \
  && "$(jq -r '.repository.full_name' <<<"$publisher_run")" == "$REPOSITORY" \
  && "$(jq -r '.head_repository.id' <<<"$publisher_run")" == "$repository_id" \
  && "$(jq -r '.head_repository.full_name' <<<"$publisher_run")" == "$REPOSITORY" \
  && "$(jq -r '.actor.id' <<<"$publisher_run")" == '4525500' \
  && "$(jq -r '.triggering_actor.id' <<<"$publisher_run")" == '4525500' ]] || {
  echo 'active runtime publisher run does not match the trusted repository, source, and dispatch identity' >&2
  exit 1
}
publisher_path="$(jq -er '.path' <<<"$publisher_run")"
case "$publisher_path" in
  ".github/workflows/${WORKFLOW_PREFIX}publish-runtime.yml"|".github/workflows/${WORKFLOW_PREFIX}publish-runtime.yml@refs/heads/$DEFAULT_BRANCH")
    signer_workflow="$REPOSITORY/.github/workflows/${WORKFLOW_PREFIX}publish-runtime.yml" ;;
  ".github/workflows/${WORKFLOW_PREFIX}control-bootstrap.yml"|".github/workflows/${WORKFLOW_PREFIX}control-bootstrap.yml@refs/heads/$DEFAULT_BRANCH")
    [[ "$(jq -r '.run_attempt' <<<"$publisher_run")" == 1 ]] || { echo 'bootstrap publisher must be the first run attempt' >&2; exit 1; }
    signer_workflow="$REPOSITORY/.github/workflows/${WORKFLOW_PREFIX}control-bootstrap.yml" ;;
  *) echo 'active runtime publisher workflow is not trusted' >&2; exit 1 ;;
esac

release="$(gh api "repos/$REPOSITORY/releases/$release_id")"
[[ "$(jq -r '.id' <<<"$release")" == "$release_id" && "$(jq -r '.draft' <<<"$release")" == 'false' && "$(jq -r '.immutable' <<<"$release")" == 'true' ]] || { echo 'active runtime release is not the selected immutable published release' >&2; exit 1; }
[[ "$(jq --argjson id "$asset_id" '[.assets[]? | select(.id == $id and .name == "securefix-runtime-linux-x86_64.tar.gz")] | length' <<<"$release")" == '1' ]] || { echo 'active runtime asset does not belong to the selected release' >&2; exit 1; }
gh api "repos/$REPOSITORY/releases/assets/$asset_id" -H 'Accept: application/octet-stream' > "$archive"
actual_size="$(stat -c %s "$archive")"
[[ "$actual_size" -gt 0 && "$actual_size" -le 134217728 ]] || { echo 'runtime archive exceeds size limit' >&2; exit 1; }
actual_sha="$(sha256sum "$archive" | cut -d ' ' -f 1)"
[[ "$actual_sha" == "$expected_archive_sha" ]] || { echo 'runtime archive digest differs from active descriptor' >&2; exit 1; }
gh attestation verify "$archive" --repo "$REPOSITORY" --source-digest "$source_sha" --source-ref "refs/heads/$DEFAULT_BRANCH" --signer-workflow "$signer_workflow" --signer-digest "$source_sha" --cert-oidc-issuer https://token.actions.githubusercontent.com --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners

runtime_dir="$(mktemp -d "$RUNNER_TEMP/securefix-runtime.XXXXXX")"
tar -xzf "$archive" -C "$runtime_dir" --no-same-owner
cp "$descriptor" "$runtime_dir/control.json"
policy_sha="$(sha256sum "$runtime_dir/policy.json" | cut -d ' ' -f 1)"
[[ "$policy_sha" == "$(jq -r '.policy_sha256' "$descriptor")" ]] || { echo 'runtime policy digest differs from active descriptor' >&2; exit 1; }
[[ "$(jq -r '.deployment.workflow_prefix // ""' "$runtime_dir/policy.json")" == "$WORKFLOW_PREFIX" ]] || { echo 'runtime workflow namespace differs from the trusted loader configuration' >&2; exit 1; }
"$runtime_dir/securefix" runtime verify --source-sha "$source_sha" --repository "$REPOSITORY" --archive "$archive"
control_outputs="$("$runtime_dir/securefix" control identify --descriptor "$runtime_dir/control.json")"
control_id="$(sed -n 's/^control-id=//p' <<<"$control_outputs")"
[[ "$control_id" =~ ^[0-9a-f]{64}$ ]] || { echo 'control identity is invalid' >&2; exit 1; }
for field in source-sha generation policy-sha256 archive-sha256 release-id asset-id; do
  key="${field//-/_}"
  value="$(sed -n "s/^$field=//p" <<<"$control_outputs")"
  expected="$(jq -r --arg key "$key" '.[$key]' "$descriptor")"
  [[ -n "$value" && "$value" == "$expected" ]] || { echo "control descriptor field mismatch: $field" >&2; exit 1; }
done
echo "directory=$runtime_dir" >> "$GITHUB_OUTPUT"
echo "source-sha=$source_sha" >> "$GITHUB_OUTPUT"
echo "control-id=$control_id" >> "$GITHUB_OUTPUT"
echo "main-sha=$main_sha" >> "$GITHUB_OUTPUT"
