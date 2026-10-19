#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$ACTION_PATH/../../.." && pwd)"
source_sha="$(git -C "$root" rev-parse HEAD)"
artifact_name="securefix-cli-ubuntu-24.04-x64-rust-1.99.0-$source_sha"
destination="$RUNNER_TEMP/securefix-cli-extract-$source_sha"

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

# Extract only the two fixed artifact members and cap decompression size.
extract_member() {
  local archive="$1" member="$2" output="$3" limit=$((50 * 1024 * 1024))
  local -a status
  set +e
  unzip -p "$archive" "$member" 2>/dev/null | head -c "$((limit + 1))" >"$output"
  status=("${PIPESTATUS[@]}")
  set -e
  [[ "${status[0]}" == 0 && "${status[1]}" == 0 && "$(stat -c %s "$output")" -gt 0 && "$(stat -c %s "$output")" -le "$limit" ]]
}

# Pull request code is always built from the checkout. Only completed, first
# attempt CI runs on the protected main branch can supply a reusable binary.
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
          extracted="$destination"
          if gh api "repos/civitaspo/securefix-server/actions/artifacts/$artifact_id/zip" >"$archive" 2>/dev/null; then
            actual_digest="$(sha256sum "$archive" | cut -d ' ' -f 1)"
            if [[ "$actual_digest" == "$expected_digest" ]]; then
              rm -rf "$extracted"
              mkdir -p "$extracted"
              if members="$(unzip -Z1 "$archive" 2>/dev/null)"; then
                sorted_members="$(printf '%s\n' "$members" | LC_ALL=C sort)"
              else
                sorted_members=
              fi
              if [[ "$sorted_members" == $'policy.json\nsecurefix' ]] && extract_member "$archive" securefix "$extracted/securefix" && extract_member "$archive" policy.json "$extracted/policy.json"; then
                if cmp -s "$extracted/policy.json" "$root/policy.json"; then
                  mkdir -p "$root/target/release"
                  install -m 755 "$extracted/securefix" "$root/target/release/securefix"
                  install -m 644 "$extracted/policy.json" "$root/target/release/policy.json"
                  echo "binary=$root/target/release/securefix" >> "$GITHUB_OUTPUT"
                  echo "reused=true" >> "$GITHUB_OUTPUT"
                  echo "Reused CLI artifact $artifact_id (sha256:$expected_digest) from CI run $run_id for $source_sha"
                  exit 0
                fi
                echo "CI artifact policy does not match the checked out source; building locally."
              else
                echo "CI artifact layout was invalid; building locally."
              fi
            else
              echo "CI artifact digest did not match its Actions API metadata; building locally."
            fi
          fi
        fi
      fi
    fi
  fi
fi

echo "No unique qualified CI artifact for $source_sha; building this checkout."
