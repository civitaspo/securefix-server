#!/usr/bin/env bash
set -euo pipefail

root="$GITHUB_WORKSPACE"
checkout_sha="$(git -C "$root" rev-parse HEAD)"
source_sha="${CANDIDATE_SOURCE_SHA:-$checkout_sha}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Candidate source SHA is invalid."; exit 1; }
artifact_name="securefix-cli-ubuntu-24.04-x64-rust-1.99.0-$source_sha"

# The artifact is only built on this exact runner image/architecture and with
# the default locked Cargo build settings used by CI.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]] || { [[ "${ImageOS:-}" != ubuntu24 ]] && ! grep -q '^VERSION_ID="24.04"$' /etc/os-release; }; then
  echo "This runner does not match the qualified CLI build platform; building locally."
  exit 0
fi
for setting in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET RUSTC_WRAPPER; do
  if [[ -n "${!setting:-}" ]]; then
    echo "Build override $setting is set; building locally."
    exit 0
  fi
done
if ! git -C "$root" diff --quiet HEAD --; then
  echo "The source checkout has tracked changes; building locally."
  exit 0
fi
if [[ -n "$(git -C "$root" ls-files --others --exclude-standard)" ]]; then
  echo "The source checkout has untracked files; building locally."
  exit 0
fi

extract_member() {
  local archive="$1" member="$2" output="$3" limit=$((50 * 1024 * 1024))
  local -a status
  set +e
  unzip -p "$archive" "$member" 2>/dev/null | head -c "$((limit + 1))" >"$output"
  status=("${PIPESTATUS[@]}")
  set -e
  [[ "${status[0]}" == 0 && "${status[1]}" == 0 && "$(stat -c %s "$output")" -gt 0 && "$(stat -c %s "$output")" -le "$limit" ]]
}

reuse_cli_artifact() {
  local archive="$1" digest="$2" artifact_id="$3" source="$4" producer_run="$5" kind="$6" workflow_sha="${7:-}"
  local actual_digest extracted members expected_members
  actual_digest="$(sha256sum "$archive" | cut -d ' ' -f 1)" || return 1
  [[ "$actual_digest" == "$digest" ]] || { echo "Reusable artifact $artifact_id digest mismatch; building locally."; return 1; }
  extracted="$RUNNER_TEMP/securefix-cli-extract-$source"
  rm -rf "$extracted" || return 1
  mkdir -p "$extracted" || return 1
  members="$(unzip -Z1 "$archive" 2>/dev/null | LC_ALL=C sort)" || return 1
  if [[ "$kind" == ci ]]; then
    expected_members=$'policy.json\nsecurefix'
  else
    expected_members=$'build.json\npolicy.json\nsecurefix'
  fi
  [[ "$members" == "$expected_members" ]] || { echo "Reusable artifact $artifact_id layout invalid; building locally."; return 1; }
  extract_member "$archive" securefix "$extracted/securefix" || return 1
  extract_member "$archive" policy.json "$extracted/policy.json" || return 1
  cmp -s "$extracted/policy.json" "$root/policy.json" || { echo "Reusable artifact $artifact_id policy differs from checked source; building locally."; return 1; }
  if [[ "$kind" == candidate ]]; then
    extract_member "$archive" build.json "$extracted/build.json" || return 1
    jq -e --arg source "$source" --arg workflow "$workflow_sha" '
      .source_sha == $source and .workflow_sha == $workflow and
      .platform == "ubuntu-24.04-x86_64" and .rust == "1.99.0" and
      .profile == "release" and .locked == true
    ' "$extracted/build.json" >/dev/null 2>&1 || { echo "Candidate artifact $artifact_id build identity differs; building locally."; return 1; }
  fi
  mkdir -p "$root/target/release" || return 1
  install -m 755 "$extracted/securefix" "$root/target/release/securefix" || return 1
  install -m 644 "$extracted/policy.json" "$root/target/release/policy.json" || return 1
  echo "binary=$root/target/release/securefix" >> "$GITHUB_OUTPUT" || return 1
  echo "reused=true" >> "$GITHUB_OUTPUT" || return 1
  if [[ "$kind" == ci ]]; then
    echo "Reused CLI artifact $artifact_id (sha256:$digest) from CI run $producer_run for $source"
  else
    echo "Reused candidate CLI artifact $artifact_id (sha256:$digest) from run $producer_run for $source"
  fi
}

if [[ "$EVENT_NAME" != pull_request && "$EVENT_NAME" != pull_request_target && -n "${GH_TOKEN:-}" ]]; then
  if server="$(gh api repos/civitaspo/securefix-server 2>/dev/null)"; then
    server_id="$(jq -r '.id // empty' <<<"$server")"
  else
    server_id=
  fi
  if [[ "$server_id" =~ ^[1-9][0-9]*$ ]] && run_list="$(gh api "repos/civitaspo/securefix-server/actions/workflows/ci.yml/runs?head_sha=$source_sha&branch=main&event=push&per_page=100" 2>/dev/null)"; then
      run="$(jq -cer --arg sha "$source_sha" --argjson server_id "$server_id" '
      if .total_count == (.workflow_runs | length) then [.workflow_runs[] | select(
        (.path == ".github/workflows/ci.yml" or .path == ".github/workflows/ci.yml@refs/heads/main") and
        .event == "push" and .head_branch == "main" and .head_sha == $sha and
        .repository.id == $server_id and .repository.full_name == "civitaspo/securefix-server" and
        .head_repository.id == $server_id and .head_repository.full_name == "civitaspo/securefix-server" and
        .status == "completed" and .conclusion == "success" and .run_attempt == 1 and .id > 0
      )] | if length == 1 then .[0] else empty end else empty end
    ' <<<"$run_list" 2>/dev/null || true)"
    if [[ -n "$run" ]]; then
      run_id="$(jq -r '.id' <<<"$run")"
      if artifact_list="$(gh api "repos/civitaspo/securefix-server/actions/runs/$run_id/artifacts?per_page=100" 2>/dev/null)"; then
        artifact="$(jq -cer --arg name "$artifact_name" --argjson run_id "$run_id" --argjson server_id "$server_id" --arg sha "$source_sha" '
          [.artifacts[] | select(
            .name == $name and .expired == false and
            .id > 0 and .workflow_run.id == $run_id and
            .workflow_run.repository_id == $server_id and .workflow_run.head_repository_id == $server_id and
            .workflow_run.head_branch == "main" and .workflow_run.head_sha == $sha and
            .size_in_bytes > 0 and .size_in_bytes <= 52428800 and
            (.digest | test("^sha256:[0-9a-f]{64}$"))
          )] | if length == 1 then .[0] else empty end
        ' <<<"$artifact_list" 2>/dev/null || true)"
        if [[ -n "$artifact" ]]; then
          artifact_id="$(jq -r '.id' <<<"$artifact")"
          expected_digest="$(jq -r '.digest | sub("^sha256:"; "")' <<<"$artifact")"
          archive="$RUNNER_TEMP/securefix-cli-$source_sha.zip"
          if gh api "repos/civitaspo/securefix-server/actions/artifacts/$artifact_id/zip" >"$archive" 2>/dev/null &&
             reuse_cli_artifact "$archive" "$expected_digest" "$artifact_id" "$source_sha" "$run_id" ci; then
            exit 0
          fi
        fi
      fi
    fi
  fi
fi

candidate_event=false
if [[ "$EVENT_NAME" == workflow_dispatch ]] || {
  [[ "$EVENT_NAME" == pull_request_target && "${CANDIDATE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
}; then
  candidate_event=true
fi

if [[ "$candidate_event" == true && "${CANDIDATE_RUN_ID:-}" =~ ^[1-9][0-9]*$ && -n "${GH_TOKEN:-}" ]]; then
  candidate_run_id="$CANDIDATE_RUN_ID"
  if candidate_run="$(gh api "repos/civitaspo/securefix-server/actions/runs/$candidate_run_id" 2>/dev/null)"; then
    candidate_branch="$(jq -r '.head_branch // empty' <<<"$candidate_run")"
    candidate_path="$(jq -r '.path // empty' <<<"$candidate_run")"
    candidate_workflow_sha="$(jq -r '.head_sha // empty' <<<"$candidate_run")"
    candidate_workflow=".github/workflows/testing-securefix-server.yml"
    if [[ "$(jq -r '.id' <<<"$candidate_run")" == "$candidate_run_id" &&
          "$(jq -r '.repository.id' <<<"$candidate_run")" == 1250079425 &&
          "$(jq -r '.repository.full_name' <<<"$candidate_run")" == civitaspo/securefix-server &&
          "$(jq -r '.head_repository.id' <<<"$candidate_run")" == 1250079425 &&
          "$(jq -r '.head_repository.full_name' <<<"$candidate_run")" == civitaspo/securefix-server &&
          "$(jq -r '.event' <<<"$candidate_run")" == workflow_dispatch &&
          "$(jq -r '.status' <<<"$candidate_run")" == completed &&
          "$(jq -r '.conclusion' <<<"$candidate_run")" == success &&
          "$(jq -r '.run_attempt' <<<"$candidate_run")" == 1 &&
          "$(jq -r '.actor.id' <<<"$candidate_run")" == 4525500 &&
          "$(jq -r '.triggering_actor.id' <<<"$candidate_run")" == 4525500 &&
          ( "$candidate_branch" == main || "$candidate_branch" == integration/native-* ) &&
          ( "$candidate_path" == "$candidate_workflow" || "$candidate_path" == "$candidate_workflow@refs/heads/$candidate_branch" ) ]]; then
      if candidate_artifacts="$(gh api "repos/civitaspo/securefix-server/actions/runs/$candidate_run_id/artifacts?per_page=100" 2>/dev/null)"; then
        candidate_artifact="$(jq -cer --argjson run_id "$candidate_run_id" --arg workflow "$candidate_workflow_sha" '
          [.artifacts[] | select(
            .name == "candidate-runtime" and .expired == false and
            .id > 0 and .workflow_run.id == $run_id and
            .workflow_run.repository_id == 1250079425 and
            .workflow_run.head_repository_id == 1250079425 and
            .workflow_run.head_sha == $workflow and
            .size_in_bytes > 0 and .size_in_bytes <= 52428800 and
            (.digest | test("^sha256:[0-9a-f]{64}$"))
          )] | if length == 1 then .[0] else empty end
        ' <<<"$candidate_artifacts" 2>/dev/null || true)"
        if [[ -n "$candidate_artifact" ]]; then
          candidate_artifact_id="$(jq -r '.id' <<<"$candidate_artifact")"
          candidate_digest="$(jq -r '.digest | sub("^sha256:"; "")' <<<"$candidate_artifact")"
          candidate_archive="$RUNNER_TEMP/securefix-candidate-$source_sha.zip"
          if gh api "repos/civitaspo/securefix-server/actions/artifacts/$candidate_artifact_id/zip" >"$candidate_archive" 2>/dev/null &&
             reuse_cli_artifact "$candidate_archive" "$candidate_digest" "$candidate_artifact_id" "$source_sha" "$candidate_run_id" candidate "$candidate_workflow_sha"; then
            exit 0
          fi
        fi
      fi
    fi
  fi
fi

echo "No qualified reusable artifact for $source_sha; building this checkout."
