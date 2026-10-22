#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "$1" >&2
  exit 1
}

manifest() {
  local input="$1" output="$2"
  jq -e '
    def workflow: type == "string" and test("^\\.github/workflows/[A-Za-z0-9._/-]+\\.yml$") and (contains("..") | not);
    def semver: type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$");
    def base: ["assets","component","max_bytes","producer_workflow","protocol","publisher_workflow","schema_version","version"];
    type == "object"
    and (.schema_version | type == "number" and floor == . and . == 2)
    and (keys == base)
    and .component == "securefix-server"
    and .protocol == "securefix-native-request/v1"
    and (.version | semver)
    and (.producer_workflow | workflow)
    and (.publisher_workflow | workflow)
    and (.max_bytes | type == "number" and floor == . and . > 0 and . <= 536870912)
    and (.assets | type == "object" and keys == ["linux-x86_64"] and (. ["linux-x86_64"] | type == "string" and test("^[A-Za-z0-9._-]+$")))
  ' "$input" >/dev/null || fail 'package manifest does not match a supported exact schema'

  jq -c '{schema_version, version, source_sha: (.source_sha // ""), producer_workflow, publisher_workflow: (.publisher_workflow // ""), max_bytes, asset_name: .assets["linux-x86_64"]}' "$input" > "$output"
}

release_record() {
  local release_path="$1" output="$2" source_sha="$3" manifest_sha="$4" producer_workflow="$5"
  local producer_run_id="$6" producer_attempt="$7" tag="$8" asset_name="$9" asset_size="${10}" asset_sha="${11}" publisher_workflow="${12}"
  local body record_path canonical

  body="$(jq -er '.body | select(type == "string" and length > 0 and length <= 16384)' "$release_path")" || fail 'schema-2 package release has no bounded publication record'
  record_path="${output}.record"
  printf '%s' "$body" > "$record_path"
  jq -e --arg source_sha "$source_sha" --arg manifest_sha "$manifest_sha" \
    --arg producer_workflow "$producer_workflow" --arg producer_run_id "$producer_run_id" --arg producer_attempt "$producer_attempt" \
    --arg tag "$tag" --arg asset_name "$asset_name" --arg asset_size "$asset_size" --arg asset_sha "$asset_sha" \
    --arg publisher_workflow "$publisher_workflow" '
      def positive: type == "number" and floor == . and . > 0;
      def sha40: type == "string" and test("^[0-9a-f]{40}$");
      def sha64: type == "string" and test("^[0-9a-f]{64}$");
      type == "object"
      and (keys == ["asset_name","asset_sha256","asset_size","producer_run_attempt","producer_run_id","producer_workflow","publisher_run_attempt","publisher_run_id","publisher_sha","publisher_workflow","schema_version","source_manifest_sha256","source_sha","tag"])
      and .schema_version == 1
      and .source_sha == $source_sha and (.source_sha | sha40)
      and .source_manifest_sha256 == $manifest_sha and (.source_manifest_sha256 | sha64)
      and .producer_workflow == $producer_workflow
      and .producer_run_id == ($producer_run_id | tonumber) and (.producer_run_id | positive)
      and .producer_run_attempt == ($producer_attempt | tonumber) and .producer_run_attempt == 1
      and .publisher_workflow == $publisher_workflow
      and (.publisher_sha | sha40)
      and (.publisher_run_id | positive)
      and .publisher_run_attempt == 1
      and .tag == $tag
      and .asset_name == $asset_name
      and .asset_size == ($asset_size | tonumber) and (.asset_size | positive)
      and .asset_sha256 == $asset_sha and (.asset_sha256 | sha64)
    ' "$record_path" >/dev/null || fail 'schema-2 package release record differs from the verified source, publisher, or asset'

  canonical="$(jq -cn --arg source_sha "$source_sha" --arg manifest_sha "$manifest_sha" \
    --arg producer_workflow "$producer_workflow" --argjson producer_run_id "$producer_run_id" --argjson producer_attempt "$producer_attempt" \
    --arg publisher_workflow "$publisher_workflow" --arg publisher_sha "$(jq -er '.publisher_sha' "$record_path")" \
    --argjson publisher_run_id "$(jq -er '.publisher_run_id' "$record_path")" --argjson publisher_attempt "$(jq -er '.publisher_run_attempt' "$record_path")" \
    --arg tag "$tag" --arg asset_name "$asset_name" --argjson asset_size "$asset_size" --arg asset_sha "$asset_sha" \
    '{schema_version:1,source_sha:$source_sha,source_manifest_sha256:$manifest_sha,producer_workflow:$producer_workflow,producer_run_id:$producer_run_id,producer_run_attempt:$producer_attempt,publisher_workflow:$publisher_workflow,publisher_sha:$publisher_sha,publisher_run_id:$publisher_run_id,publisher_run_attempt:$publisher_attempt,tag:$tag,asset_name:$asset_name,asset_size:$asset_size,asset_sha256:$asset_sha}')"
  [[ "$canonical" == "$body" ]] || fail 'schema-2 package release record is not canonical compact JSON'
  jq -c '{publisher_sha, publisher_run_id, publisher_run_attempt}' "$record_path" > "$output"
  rm -f "$record_path"
}

publisher_run() {
  local run_path="$1" run_id="$2" attempt="$3" repository="$4" repository_id="$5" branch="$6" workflow="$7" sha="$8" publisher_actor_id="$9"
  jq -e --argjson run_id "$run_id" --argjson attempt "$attempt" --arg repo "$repository" --argjson repo_id "$repository_id" \
    --arg branch "$branch" --arg workflow "$workflow" --arg sha "$sha" --argjson publisher_actor_id "$publisher_actor_id" '
      .id == $run_id and .run_attempt == $attempt and .status == "completed" and .conclusion == "success"
      and .event == "workflow_dispatch" and .head_branch == $branch and .head_sha == $sha
      and .repository.id == $repo_id and .repository.full_name == $repo
      and .head_repository.id == $repo_id and .head_repository.full_name == $repo
      and (.path == $workflow or .path == ($workflow + "@refs/heads/" + $branch))
      and .actor.id == $publisher_actor_id and .actor.type == "User"
      and .triggering_actor.id == $publisher_actor_id and .triggering_actor.type == "User"
    ' "$run_path" >/dev/null || fail 'package publisher run differs from the successful protected owner-dispatched run'
}

case "${1:-}" in
  manifest) [[ "$#" == 3 ]] || fail 'manifest validator arguments are invalid'; manifest "$2" "$3" ;;
  release-record) [[ "$#" == 13 ]] || fail 'release record validator arguments are invalid'; release_record "${@:2}" ;;
  publisher-run) [[ "$#" == 10 ]] || fail 'publisher run validator arguments are invalid'; publisher_run "${@:2}" ;;
  *) fail 'package metadata validator command is invalid' ;;
esac
