#!/usr/bin/env bash
set -euo pipefail

work="$(mktemp -d "$RUNNER_TEMP/securefix-package.XXXXXX")"
trap 'rm -rf "$work"' EXIT
manifest="$work/package.json"
[[ "$ACTION_SHA" =~ ^[0-9a-f]{40}$ && "$SOURCE_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$DESTINATION_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'package source identity is invalid' >&2; exit 1; }
[[ "$SOURCE_REPOSITORY_ID" =~ ^[1-9][0-9]{0,19}$ && "$DESTINATION_REPOSITORY_ID" =~ ^[1-9][0-9]{0,19}$ && "$OWNER_ID" =~ ^[1-9][0-9]{0,19}$ ]] || { echo 'package repository ID is invalid' >&2; exit 1; }
[[ "$SOURCE_DEFAULT_BRANCH" =~ ^[A-Za-z0-9._/-]+$ && "$SOURCE_DEFAULT_BRANCH" != *..* && -n "$GH_TOKEN" ]] || { echo 'package branch or token is invalid' >&2; exit 1; }
[[ "$CHANNEL" == stable || "$CHANNEL" == scratch ]] || { echo 'unsupported package channel' >&2; exit 1; }
if [[ "$CHANNEL" == scratch ]]; then
  if [[ "$CALLER_REPOSITORY" == "$SOURCE_REPOSITORY" && "$CALLER_REPOSITORY_ID" == "$SOURCE_REPOSITORY_ID" && "$EVENT_NAME" == 'workflow_dispatch' && "$ACTOR_ID" == "$OWNER_ID" && "$RUN_ATTEMPT" == 1 ]]; then
    :
  elif [[ "$CALLER_REPOSITORY" == 'civitaspo/testing-securefix-server' && "$CALLER_REPOSITORY_ID" == '1410312556' && "$CALLER_WORKFLOW_REF" == 'civitaspo/testing-securefix-server/.github/workflows/policy-check.yml@refs/heads/main' && "$EVENT_NAME" == 'pull_request_target' && "$RUN_ATTEMPT" == 1 ]]; then
    :
  else
    echo 'scratch package loading is restricted to the owner test host or immutable policy-check test caller' >&2
    exit 1
  fi
fi
if [[ "$CHANNEL" == scratch ]]; then
  [[ "$MANIFEST_SOURCE_SHA" =~ ^[0-9a-f]{40}$ && "$PUBLICATION_SOURCE_SHA" == "$MANIFEST_SOURCE_SHA" ]] || { echo 'scratch manifest source must equal the selected publication source SHA' >&2; exit 1; }
  manifest_response="$work/package-manifest-response.json"
  curl_config="$work/curl-config"
  printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" > "$curl_config"
  chmod 600 "$curl_config"
  curl --config "$curl_config" --fail --silent --show-error --max-time 30 --max-filesize 65536 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "https://api.github.com/repos/$SOURCE_REPOSITORY/contents/.github/actions/load-package/package.json?ref=$MANIFEST_SOURCE_SHA" \
    -o "$manifest_response"
  [[ "$(stat -c %s "$manifest_response")" -gt 0 && "$(stat -c %s "$manifest_response")" -le 65536 ]] || { echo 'scratch package manifest response is missing or too large' >&2; exit 1; }
  manifest_b64="$(jq -er 'select(.path == ".github/actions/load-package/package.json" and .encoding == "base64" and (.content | type == "string" and length > 0 and length <= 21848)) | .content' "$manifest_response")"
  printf '%s' "$manifest_b64" | tr -d '\r\n' | base64 --decode > "$manifest" || { echo 'scratch package manifest encoding is invalid' >&2; exit 1; }
else
  [[ -z "$MANIFEST_SOURCE_SHA" ]] || { echo 'stable package loads cannot override the fixed manifest source' >&2; exit 1; }
  fixed_manifest="$ACTION_PATH/package.json"
  [[ -f "$fixed_manifest" && ! -L "$fixed_manifest" && "$(stat -c %s "$fixed_manifest")" -le 16384 ]] || { echo 'fixed package manifest is missing or too large' >&2; exit 1; }
  install -m 600 "$fixed_manifest" "$manifest"
fi
[[ -f "$manifest" && ! -L "$manifest" && "$(stat -c %s "$manifest")" -le 16384 ]] || { echo 'package manifest is missing or too large' >&2; exit 1; }
validated_manifest="$work/validated-package.json"
bash "$ACTION_PATH/validate.sh" manifest "$manifest" "$validated_manifest"
schema_version="$(jq -er '.schema_version' "$validated_manifest")"
[[ "$schema_version" == 2 ]] || { echo 'this package loader requires the publisher-bound schema-2 manifest' >&2; exit 1; }
manifest_source_sha="$(jq -r '.source_sha' "$validated_manifest")"
if [[ -z "$manifest_source_sha" ]]; then
  if [[ "$CHANNEL" == scratch ]]; then manifest_source_sha="$MANIFEST_SOURCE_SHA"; else manifest_source_sha="$ACTION_SHA"; fi
else
  [[ "$manifest_source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'package binary source SHA is invalid' >&2; exit 1; }
  if [[ "$CHANNEL" == scratch ]]; then
    [[ "$manifest_source_sha" == "$MANIFEST_SOURCE_SHA" ]] || { echo 'scratch manifest binary source differs from its selected source revision' >&2; exit 1; }
  fi
fi
version="$(jq -er '.version' "$validated_manifest")"
asset_name="$(jq -er '.asset_name' "$validated_manifest")"
workflow="$(jq -er '.producer_workflow' "$validated_manifest")"
publisher_workflow="$(jq -r '.publisher_workflow' "$validated_manifest")"
limit="$(jq -er '.max_bytes' "$validated_manifest")"
[[ "$limit" =~ ^[1-9][0-9]{0,8}$ && "$limit" -le 536870912 ]] || { echo 'package size limit is invalid' >&2; exit 1; }
if [[ -n "$ACTION_REF" ]]; then
  [[ "$ACTION_REF" =~ ^[0-9a-f]{40}$ ]] || { echo 'remote package actions must use a full immutable SHA pin' >&2; exit 1; }
  [[ "$ACTION_REF" == "$ACTION_SHA" ]] || { echo 'loader SHA differs from the immutable action pin' >&2; exit 1; }
else
  checkout_sha="$(git -C "$ACTION_PATH" rev-parse HEAD 2>/dev/null || true)"
  [[ "$ACTION_PATH" == "$GITHUB_WORKSPACE"/* && "$CALLER_REPOSITORY" == "$SOURCE_REPOSITORY" && "$checkout_sha" == "$ACTION_SHA" ]] || { echo 'local action is not loaded from its selected source commit' >&2; exit 1; }
fi
if [[ "$CHANNEL" == stable ]]; then
  [[ "$SOURCE_REPOSITORY" == "$DESTINATION_REPOSITORY" && "$SOURCE_REPOSITORY_ID" == "$DESTINATION_REPOSITORY_ID" && "$version" != *-* ]] || { echo 'stable package must come from the configured source default branch' >&2; exit 1; }
else
  [[ "$SOURCE_REPOSITORY" != "$DESTINATION_REPOSITORY" && "$SOURCE_REPOSITORY_ID" != "$DESTINATION_REPOSITORY_ID" && "$version" == *-* ]] || { echo 'scratch package identity is invalid' >&2; exit 1; }
fi

tag="v$version"
source_info="$(gh api "repos/$SOURCE_REPOSITORY")"
destination_info="$(gh api "repos/$DESTINATION_REPOSITORY")"
source_owner_id="$(jq -er --arg repo "$SOURCE_REPOSITORY" --argjson id "$SOURCE_REPOSITORY_ID" --arg branch "$SOURCE_DEFAULT_BRANCH" 'select(.full_name == $repo and .id == $id and .default_branch == $branch and (.owner.id | type == "number" and . > 0)) | .owner.id' <<<"$source_info")" || { echo 'package source repository identity or default branch changed' >&2; exit 1; }
jq -e --arg repo "$DESTINATION_REPOSITORY" --argjson id "$DESTINATION_REPOSITORY_ID" '.full_name == $repo and .id == $id and (.default_branch | type == "string" and length > 0)' <<<"$destination_info" >/dev/null || { echo 'package destination repository identity changed' >&2; exit 1; }
destination_default_branch="$(jq -er '.default_branch' <<<"$destination_info")"
release="$(gh api "repos/$DESTINATION_REPOSITORY/releases/tags/$tag")"
pre=false; [[ "$CHANNEL" == scratch ]] && pre=true
release_id="$(jq -er '.id | select(type == "number" and . > 0)' <<<"$release")"
jq -e --arg tag "$tag" --argjson pre "$pre" '.tag_name == $tag and .draft == false and .immutable == true and .prerelease == $pre' <<<"$release" >/dev/null || { echo 'package release is not the expected immutable release' >&2; exit 1; }
release_record_input="$work/release-record-input.json"
printf '%s' "$release" > "$release_record_input"
release_target="$(jq -er '.target_commitish | select(type == "string" and length > 0)' <<<"$release")"
if [[ "$CHANNEL" == scratch ]]; then
  [[ "$release_target" == "$destination_default_branch" ]] || { echo 'scratch release target differs from the configured destination branch' >&2; exit 1; }
fi
jq -e --arg name "$asset_name" --argjson limit "$limit" '[.assets[]? | select(.name == $name and .state == "uploaded" and .size > 0 and .size <= $limit and (.digest | test("^sha256:[0-9a-f]{64}$")))] as $a | ($a | length) == 1 and (.assets | length) == 1' <<<"$release" >/dev/null || { echo 'package release asset set is invalid' >&2; exit 1; }
asset="$(jq -cer --arg name "$asset_name" '.assets[] | select(.name == $name)' <<<"$release")"
asset_id="$(jq -er '.id | select(type == "number" and . > 0)' <<<"$asset")"
size="$(jq -er '.size' <<<"$asset")"
digest="$(jq -er '.digest | sub("^sha256:"; "")' <<<"$asset")"

tag_ref="$(gh api "repos/$DESTINATION_REPOSITORY/git/ref/tags/$tag")"
tag_object_type="$(jq -er '.object.type' <<<"$tag_ref")"
tag_object_sha="$(jq -er '.object.sha | select(test("^[0-9a-f]{40}$"))' <<<"$tag_ref")"
if [[ "$tag_object_type" == tag ]]; then
  tag_object="$(gh api "repos/$DESTINATION_REPOSITORY/git/tags/$tag_object_sha")"
  [[ "$(jq -er '.object.type' <<<"$tag_object")" == commit ]] || { echo 'package release tag does not point directly to a commit' >&2; exit 1; }
  tag_commit="$(jq -er '.object.sha | select(test("^[0-9a-f]{40}$"))' <<<"$tag_object")"
elif [[ "$tag_object_type" == commit ]]; then
  tag_commit="$tag_object_sha"
else
  echo 'package release tag object type is unsupported' >&2
  exit 1
fi
if [[ "$CHANNEL" == scratch ]]; then
  destination_compare="$(gh api "repos/$DESTINATION_REPOSITORY/compare/$tag_commit...$destination_default_branch")"
  jq -e --arg tag "$tag_commit" '(.status == "ahead" or .status == "identical") and .base_commit.sha == $tag and .merge_base_commit.sha == $tag and (.ahead_by | type == "number" and . >= 0) and .behind_by == 0' <<<"$destination_compare" >/dev/null || { echo 'scratch package tag is not reachable from the destination default branch' >&2; exit 1; }
fi

binary="$work/$asset_name"; response="$work/attestations.json"; bundle="$work/bundle.jsonl"; preverified="$work/preverified.json"; verified="$work/verified.json"
curl --fail --silent --show-error --location --max-time 60 --max-filesize "$limit" -H 'Accept: application/octet-stream' "https://api.github.com/repos/$DESTINATION_REPOSITORY/releases/assets/$asset_id" -o "$binary"
[[ "$(stat -c %s "$binary")" == "$size" && "$size" -le "$limit" && "$(sha256sum "$binary" | cut -d ' ' -f 1)" == "$digest" ]] || { echo 'downloaded package bytes differ from release metadata' >&2; exit 1; }
curl --fail --silent --show-error --max-time 60 --max-filesize 16777216 -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "https://api.github.com/repos/$SOURCE_REPOSITORY/attestations/sha256:$digest?per_page=100" -o "$response"
[[ "$(stat -c %s "$response")" -gt 0 && "$(stat -c %s "$response")" -le 16777216 ]] || { echo 'source attestation list is missing or too large' >&2; exit 1; }
jq -e --argjson id "$SOURCE_REPOSITORY_ID" '(.attestations | type == "array" and length > 0 and length < 100) and all(.attestations[]; .repository_id == $id and (.bundle | type == "object"))' "$response" >/dev/null || { echo 'source attestation data is incomplete' >&2; exit 1; }
jq -c '.attestations[].bundle' "$response" > "$bundle"
mkdir -m 700 "$work/gh-config"
GH_TOKEN= GITHUB_TOKEN= GH_CONFIG_DIR="$work/gh-config" HOME="$work" XDG_CACHE_HOME="$work/cache" gh attestation verify "$binary" --bundle "$bundle" --repo "$SOURCE_REPOSITORY" --signer-workflow "$SOURCE_REPOSITORY/$workflow" --cert-oidc-issuer https://token.actions.githubusercontent.com --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners --format json > "$preverified"
[[ "$(stat -c %s "$preverified")" -gt 0 && "$(stat -c %s "$preverified")" -le 1048576 ]] || { echo 'attestation verifier output is missing or too large' >&2; exit 1; }
[[ "$(jq -er 'length' "$preverified")" == 1 ]] || { echo 'attestation verifier did not return exactly one source package result' >&2; exit 1; }
source_sha="$(jq -er '.[0].verificationResult.signature.certificate.sourceRepositoryDigest | select(test("^[0-9a-f]{40}$"))' "$preverified")"
[[ "$source_sha" == "$manifest_source_sha" ]] || { echo 'attested package source differs from the fixed loader mapping' >&2; exit 1; }
source_ref="$(jq -er '.[0].verificationResult.signature.certificate.sourceRepositoryRef | select(type == "string")' "$preverified")"
[[ "$source_ref" =~ ^refs/heads/([A-Za-z0-9._/-]+)$ ]] || { echo 'attested package source ref is not a branch' >&2; exit 1; }
source_branch="${BASH_REMATCH[1]}"
[[ "$source_branch" != *..* && "$source_branch" != */ && "$source_branch" != *//* ]] || { echo 'attested package source branch is not canonical' >&2; exit 1; }
signer="https://github.com/$SOURCE_REPOSITORY/$workflow@$source_ref"
jq -e --arg repo "$SOURCE_REPOSITORY" --argjson repo_id "$SOURCE_REPOSITORY_ID" --argjson source_owner_id "$source_owner_id" --arg sha "$source_sha" --arg ref "$source_ref" --arg workflow "$workflow" --arg signer "$signer" --arg name "$asset_name" --arg digest "$digest" '
  length == 1 and (.[0].verificationResult as $v | $v.signature.certificate as $c | $v.statement as $s |
  ($c.issuer == "https://token.actions.githubusercontent.com" and $c.runnerEnvironment == "github-hosted" and $c.subjectAlternativeName == $signer and
   $c.githubWorkflowRepository == $repo and $c.githubWorkflowSHA == $sha and $c.githubWorkflowRef == $ref and
   $c.buildSignerURI == $signer and $c.buildSignerDigest == $sha and
   $c.buildConfigURI == $signer and $c.buildConfigDigest == $sha and
   $c.sourceRepositoryURI == ("https://github.com/" + $repo) and $c.sourceRepositoryDigest == $sha and $c.sourceRepositoryRef == $ref and
   $c.sourceRepositoryOwnerURI == ("https://github.com/" + ($repo | split("/")[0])) and
   ($c.sourceRepositoryIdentifier | tostring) == ($repo_id | tostring) and ($c.sourceRepositoryOwnerIdentifier | tostring) == ($source_owner_id | tostring) and
   $c.buildTrigger == $c.githubWorkflowTrigger and
   $s.predicateType == "https://slsa.dev/provenance/v1" and ($s.subject | length) == 1 and $s.subject[0].name == $name and $s.subject[0].digest.sha256 == $digest))
' "$preverified" >/dev/null || { echo 'verified attestation certificate or subject differs from the fixed package' >&2; exit 1; }
source_manifest_response="$work/source-manifest-response.json"
source_manifest="$work/source-package.json"
gh api "repos/$SOURCE_REPOSITORY/contents/.github/actions/load-package/package.json?ref=$source_sha" > "$source_manifest_response"
jq -e '.path == ".github/actions/load-package/package.json" and .type == "file" and .encoding == "base64" and (.size | type == "number" and . > 0 and . <= 16384) and (.content | type == "string" and length <= 24576)' "$source_manifest_response" >/dev/null || { echo 'attested source package manifest is missing or oversized' >&2; exit 1; }
jq -erj '.content | gsub("[\\r\\n]"; "") | @base64d' "$source_manifest_response" > "$source_manifest"
cmp -s "$manifest" "$source_manifest" || { echo 'attested source package manifest differs from the fixed loader manifest' >&2; exit 1; }
manifest_digest="$(sha256sum "$source_manifest" | cut -d ' ' -f 1)"
GH_TOKEN= GITHUB_TOKEN= GH_CONFIG_DIR="$work/gh-config" HOME="$work" XDG_CACHE_HOME="$work/cache" gh attestation verify "$binary" --bundle "$bundle" --repo "$SOURCE_REPOSITORY" --signer-workflow "$SOURCE_REPOSITORY/$workflow" --signer-digest "$source_sha" --source-digest "$source_sha" --source-ref "$source_ref" --cert-oidc-issuer https://token.actions.githubusercontent.com --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners --format json > "$verified"
[[ "$(stat -c %s "$verified")" -gt 0 && "$(stat -c %s "$verified")" -le 1048576 ]] || { echo 'exact attestation verifier output is missing or too large' >&2; exit 1; }
jq -e --arg repo "$SOURCE_REPOSITORY" --argjson repo_id "$SOURCE_REPOSITORY_ID" --argjson source_owner_id "$source_owner_id" --arg sha "$source_sha" --arg ref "$source_ref" --arg workflow "$workflow" --arg signer "$signer" --arg name "$asset_name" --arg digest "$digest" '
  length == 1 and (.[0].verificationResult as $v | $v.signature.certificate as $c | $v.statement as $s |
  ($c.issuer == "https://token.actions.githubusercontent.com" and $c.runnerEnvironment == "github-hosted" and $c.subjectAlternativeName == $signer and
   $c.githubWorkflowRepository == $repo and $c.githubWorkflowSHA == $sha and $c.githubWorkflowRef == $ref and
   $c.buildSignerURI == $signer and $c.buildSignerDigest == $sha and
   $c.buildConfigURI == $signer and $c.buildConfigDigest == $sha and
   $c.sourceRepositoryURI == ("https://github.com/" + $repo) and $c.sourceRepositoryDigest == $sha and $c.sourceRepositoryRef == $ref and
   $c.sourceRepositoryOwnerURI == ("https://github.com/" + ($repo | split("/")[0])) and
   ($c.sourceRepositoryIdentifier | tostring) == ($repo_id | tostring) and ($c.sourceRepositoryOwnerIdentifier | tostring) == ($source_owner_id | tostring) and
   $c.buildTrigger == $c.githubWorkflowTrigger and
   $s.predicateType == "https://slsa.dev/provenance/v1" and ($s.subject | length) == 1 and $s.subject[0].name == $name and $s.subject[0].digest.sha256 == $digest))
' "$verified" >/dev/null || { echo 'exact attestation verification differs from the fixed package' >&2; exit 1; }
run_uri="$(jq -er '.[0].verificationResult.signature.certificate.runInvocationURI' "$verified")"
if [[ "$run_uri" =~ ^https://github\.com/([^/]+/[^/]+)/actions/runs/([1-9][0-9]*)/attempts/([1-9][0-9]*)$ ]]; then repo_in_run="${BASH_REMATCH[1]}"; run_id="${BASH_REMATCH[2]}"; attempt="${BASH_REMATCH[3]}"; else echo 'attestation run URI is invalid' >&2; exit 1; fi
[[ "$repo_in_run" == "$SOURCE_REPOSITORY" ]] || { echo 'attestation run belongs to another repository' >&2; exit 1; }
trigger="$(jq -er '.[0].verificationResult.signature.certificate.githubWorkflowTrigger | select(type == "string" and length > 0)' "$verified")"
run="$(gh api "repos/$SOURCE_REPOSITORY/actions/runs/$run_id/attempts/$attempt")"
jq -e --arg repo "$SOURCE_REPOSITORY" --argjson repo_id "$SOURCE_REPOSITORY_ID" --argjson owner "$OWNER_ID" --arg branch "$source_branch" --arg sha "$source_sha" --arg workflow "$workflow" --arg trigger "$trigger" --arg channel "$CHANNEL" --argjson run "$run_id" --argjson attempt "$attempt" '.id == $run and .run_attempt == $attempt and .status == "completed" and .conclusion == "success" and .event == $trigger and .head_branch == $branch and .head_sha == $sha and .repository.id == $repo_id and .repository.full_name == $repo and .head_repository.id == $repo_id and .head_repository.full_name == $repo and (.path == $workflow or .path == ($workflow + "@refs/heads/" + $branch)) and ($channel != "scratch" or (.event == "workflow_dispatch" and .actor.id == $owner and .actor.type == "User" and .triggering_actor.id == $owner and .triggering_actor.type == "User"))' <<<"$run" >/dev/null || { echo 'producer run differs from the verified source attempt' >&2; exit 1; }
release_record="$work/release-record.json"
bash "$ACTION_PATH/validate.sh" release-record "$release_record_input" "$release_record" "$source_sha" "$manifest_digest" "$workflow" "$run_id" "$attempt" "$tag" "$asset_name" "$size" "$digest" "$publisher_workflow"
publisher_sha="$(jq -er '.publisher_sha' "$release_record")"
publisher_run_id="$(jq -er '.publisher_run_id' "$release_record")"
publisher_run_attempt="$(jq -er '.publisher_run_attempt' "$release_record")"
[[ "$publisher_sha" =~ ^[0-9a-f]{40}$ && "$publisher_run_id" =~ ^[1-9][0-9]{0,19}$ && "$publisher_run_attempt" == 1 ]] || { echo 'package publisher identity is invalid' >&2; exit 1; }
publisher_run_path="$work/publisher-run.json"
gh api "repos/$SOURCE_REPOSITORY/actions/runs/$publisher_run_id/attempts/$publisher_run_attempt" > "$publisher_run_path"
bash "$ACTION_PATH/validate.sh" publisher-run "$publisher_run_path" "$publisher_run_id" "$publisher_run_attempt" "$SOURCE_REPOSITORY" "$SOURCE_REPOSITORY_ID" "$SOURCE_DEFAULT_BRANCH" "$publisher_workflow" "$publisher_sha" "$OWNER_ID"
if [[ "$CHANNEL" == stable ]]; then
  [[ "$source_branch" == "$SOURCE_DEFAULT_BRANCH" && "$tag_commit" == "$source_sha" && "$release_target" == "$source_sha" ]] || { echo 'stable package release tag differs from the attested default-branch source' >&2; exit 1; }
fi
if [[ "$CHANNEL" == scratch ]]; then
  [[ "$PUBLICATION_SOURCE_SHA" =~ ^[0-9a-f]{40}$ && "$PUBLICATION_ASSET_SHA256" =~ ^[0-9a-f]{64}$ && "$PUBLICATION_RELEASE_ID" =~ ^[1-9][0-9]{0,19}$ && "$PUBLICATION_ASSET_ID" =~ ^[1-9][0-9]{0,19}$ && "$PUBLICATION_ASSET_SIZE" =~ ^[1-9][0-9]{0,19}$ && "$PUBLICATION_PRODUCER_RUN_ID" =~ ^[1-9][0-9]{0,19}$ && "$PUBLICATION_PRODUCER_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,19}$ ]] || { echo 'scratch publication record is incomplete' >&2; exit 1; }
  [[ "$PUBLICATION_SOURCE_SHA" == "$source_sha" && "$PUBLICATION_SOURCE_BRANCH" == "$source_branch" && "$PUBLICATION_TAG" == "$tag" && "$PUBLICATION_RELEASE_ID" == "$release_id" && "$PUBLICATION_ASSET_ID" == "$asset_id" && "$PUBLICATION_ASSET_SHA256" == "$digest" && "$PUBLICATION_ASSET_SIZE" == "$size" && "$PUBLICATION_PRODUCER_RUN_ID" == "$run_id" && "$PUBLICATION_PRODUCER_RUN_ATTEMPT" == "$attempt" ]] || { echo 'verified package differs from the current scratch publication record' >&2; exit 1; }
fi
install_dir="$(mktemp -d "$RUNNER_TEMP/securefix-package-$source_sha.XXXXXX")"; chmod 700 "$install_dir"; install -m 755 "$binary" "$install_dir/securefix"; echo "$install_dir" >> "$GITHUB_PATH"
echo "binary=$install_dir/securefix" >> "$GITHUB_OUTPUT"; echo "version=$version" >> "$GITHUB_OUTPUT"; echo "asset-id=$asset_id" >> "$GITHUB_OUTPUT"; echo "release-id=$release_id" >> "$GITHUB_OUTPUT"; echo "source-sha=$source_sha" >> "$GITHUB_OUTPUT"; echo "source-branch=$source_branch" >> "$GITHUB_OUTPUT"; echo "producer-run-id=$run_id" >> "$GITHUB_OUTPUT"; echo "producer-run-attempt=$attempt" >> "$GITHUB_OUTPUT"
