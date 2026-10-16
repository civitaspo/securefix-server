#!/usr/bin/env python3
"""Fixed GitHub API writer for the explicitly reviewed one-time bootstrap."""

import argparse
import base64
import io
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
ACTIVE = "control/active.json"
ASSET = "securefix-runtime-linux-x86_64.tar.gz"
ZERO = "0" * 64
BOOTSTRAP_WORKFLOW = ".github/workflows/control-bootstrap.yml"
TEST_WORKFLOW = ".github/workflows/testing-securefix-server.yml"
LEGACY_SOURCE_SHA = "e8e2bc77d96a4e359417217f1d1c22f4e1ac4483"
LEGACY_TAG = "v0.2.20"
OWNER_ID = 4525500
SERVER_ID = 1250079425
STATUS_APP_ID = 15368
SERVER_BOT_ID = 288069019
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_ARTIFACT = 64 * 1024
MAX_TAR_MEMBERS = 4096
MAX_TAR_UNPACKED = 512 * 1024 * 1024


def checked(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical_control_id(descriptor):
    fields = (
        "version", "generation", "source_sha", "policy_sha256", "archive_sha256",
        "release_id", "asset_id", "publisher_run_id", "verification_run_id", "previous",
    )
    checked(set(descriptor) == set(fields), "descriptor schema mismatch")
    ordered = {field: descriptor[field] for field in fields}
    return hashlib.sha256(json.dumps(ordered, separators=(",", ":")).encode()).hexdigest()


def contents(repo, path, revision):
    response = request("GET", repo_path(repo, f"contents/{path}?ref={urllib.parse.quote(revision, safe='')}"))
    checked(response.get("type") == "file" and response.get("path") == path, "source content identity mismatch")
    checked(response.get("encoding") == "base64" and isinstance(response.get("content"), str), "source content encoding is unsupported")
    raw = base64.b64decode(response["content"], validate=False)
    checked(len(raw) == response.get("size") and len(raw) <= 1024 * 1024, "source content size mismatch")
    return raw


def current_policy(repo, source):
    raw = contents(repo, "policy.json", source)
    current = json.load(open("policy.json", "rb"))
    candidate = json.loads(raw)
    checked(candidate == current, "candidate policy differs from trusted workflow checkout policy")
    dep = candidate["deployment"]
    checked(candidate["owner_id"] == OWNER_ID and dep["repository_owner"]["id"] == OWNER_ID, "policy owner identity mismatch")
    checked(dep["server"] == {"repository": repo, "id": SERVER_ID, "default_branch": "main"}, "policy server repository identity mismatch")
    checked(candidate["server_bot_id"] == SERVER_BOT_ID and dep["checks"]["status_app_id"] == STATUS_APP_ID, "policy bot or required check identity mismatch")
    return candidate, raw


def workflow_run(repo, run_id, workflow, source=None, status="completed"):
    run = request("GET", repo_path(repo, f"actions/runs/{run_id}"))
    checked(run.get("id") == int(run_id) and run.get("repository", {}).get("full_name") == repo and run.get("repository", {}).get("id") == SERVER_ID, "workflow run repository identity mismatch")
    checked(run.get("head_repository", {}).get("full_name") == repo and run.get("head_repository", {}).get("id") == SERVER_ID, "workflow run head repository mismatch")
    checked(run.get("path") in (workflow, f"{workflow}@refs/heads/main") and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main" and run.get("run_attempt") == 1, "workflow run is not first-attempt owner dispatch from main")
    checked(run.get("actor", {}).get("id") == OWNER_ID and run.get("triggering_actor", {}).get("id") == OWNER_ID, "workflow run actor is not the configured owner")
    if source is not None:
        checked(run.get("head_sha") == source, "workflow run source SHA mismatch")
    if status == "in_progress":
        checked(run.get("status") == "in_progress", "current bootstrap workflow run is not in progress")
    else:
        checked(run.get("status") == "completed" and run.get("conclusion") == "success", "evidence workflow run did not complete successfully")
    return run


def required_status(repo, sha):
    commit = request("GET", repo_path(repo, f"commits/{sha}"))
    checked(commit.get("sha") == sha and commit.get("commit", {}).get("verification", {}).get("verified") is True, "source commit signature is not verified")
    combined = request("GET", repo_path(repo, f"commits/{sha}/status"))
    checked(combined.get("total_count", 0) == 0 or combined.get("state") == "success", "combined commit status is failing")
    matches = []
    for page in range(1, 101):
        checks = request("GET", repo_path(repo, f"commits/{sha}/check-runs?per_page=100&page={page}&filter=latest"))
        batch = checks.get("check_runs", [])
        matches.extend(c for c in batch if c.get("name") == "status-check" and c.get("app", {}).get("id") == STATUS_APP_ID)
        if len(batch) < 100:
            break
    checked(len(matches) == 1 and matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success", "required status-check is not unique and successful")


def verify_attestation(archive_path, repo, source, workflow):
    env = os.environ.copy()
    # In writer jobs GH_TOKEN is the Server App credential. Attestation reads
    # must use the separate, read-only workflow token.
    if env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    result = subprocess.run([
        "gh", "attestation", "verify", archive_path,
        "--repo", repo,
        "--source-digest", source,
        "--source-ref", "refs/heads/main",
        "--signer-workflow", f"{repo}/{workflow}",
        "--signer-digest", source,
        "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--predicate-type", "https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, env=env)
    checked(result.returncode == 0, "archive attestation verification failed")


def verify_published_immutable_archive(repo, release, source, source_policy):
    checked(release.get("immutable") is True and release.get("draft") is False,
            "reserved bootstrap release is not immutable and published")
    assets = release.get("assets", [])
    checked(len(assets) == 1, "immutable bootstrap release must contain exactly one asset")
    asset = assets[0]
    checked(asset.get("name") == ASSET and asset.get("state") == "uploaded"
            and isinstance(asset.get("id"), int) and asset["id"] > 0
            and isinstance(asset.get("size"), int) and 0 < asset["size"] <= MAX_ARCHIVE
            and re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")) is not None,
            "immutable bootstrap asset metadata is invalid")
    raw = request_bytes(repo_path(repo, f"releases/assets/{asset['id']}"), MAX_ARCHIVE)
    digest = hashlib.sha256(raw).hexdigest()
    checked(len(raw) == asset["size"] and digest == asset["digest"].removeprefix("sha256:"),
            "immutable bootstrap asset download differs from GitHub metadata")
    with tempfile.NamedTemporaryFile() as archive_file:
        archive_file.write(raw)
        archive_file.flush()
        actual_digest, archived_policy = archive_policy(archive_file.name)
        checked(actual_digest == digest and archived_policy == source_policy,
                "immutable bootstrap archive does not contain the exact trusted source policy")
        verify_attestation(archive_file.name, repo, source, BOOTSTRAP_WORKFLOW)
    return digest


def archive_policy(archive_path):
    with open(archive_path, "rb") as stream:
        raw_archive = stream.read(MAX_ARCHIVE + 1)
    checked(len(raw_archive) <= MAX_ARCHIVE, "candidate archive is oversized")
    digest = hashlib.sha256(raw_archive).hexdigest()
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:gz") as archive:
        policy = None
        seen = set()
        unpacked = 0
        count = 0
        for member in archive:
            count += 1
            checked(count <= MAX_TAR_MEMBERS, "candidate archive has too many entries")
            name = member.name
            checked(name not in seen, "candidate archive has duplicate paths")
            seen.add(name)
            normalized = name.removeprefix("./")
            checked(not name.startswith("/") and ".." not in normalized.split("/"), "candidate archive contains an unsafe path")
            checked(member.isdir() or member.isfile(), "candidate archive contains a link or special file")
            checked(not member.issparse() and 0 <= member.size <= MAX_TAR_UNPACKED, "candidate archive contains an oversized or sparse entry")
            unpacked += member.size
            checked(unpacked <= MAX_TAR_UNPACKED, "candidate archive expands beyond the size limit")
            if normalized == "policy.json":
                checked(member.isfile() and member.size <= 256 * 1024 and policy is None, "candidate archive has unsafe/duplicate policy.json")
                stream = archive.extractfile(member)
                checked(stream is not None, "candidate archive policy cannot be read")
                policy = stream.read(256 * 1024 + 1)
                checked(len(policy) == member.size and len(policy) <= 256 * 1024, "candidate archive policy size mismatch")
        checked(policy is not None, "candidate archive is missing policy.json")
    return digest, policy


def zip_json_files(artifact_bytes, names):
    import zipfile
    checked(len(artifact_bytes) <= MAX_ARTIFACT, "scratch artifact zip is oversized")
    with zipfile.ZipFile(io.BytesIO(artifact_bytes)) as archive:
        infos = archive.infolist()
        checked({i.filename for i in infos} == set(names) and len(infos) == len(names), "scratch artifact has unexpected file set")
        result = {}
        for info in infos:
            mode = info.external_attr >> 16
            checked((mode & 0o170000) != 0o120000 and info.file_size <= MAX_ARTIFACT, "scratch artifact has unsafe file")
            raw = archive.read(info)
            checked(len(raw) == info.file_size, "scratch artifact file size mismatch")
            result[info.filename] = json.loads(raw)
        return result


def artifact_bytes(repo, run_id, artifact_name, max_size):
    data = request("GET", repo_path(repo, f"actions/runs/{run_id}/artifacts?per_page=100"))
    matches = [a for a in data.get("artifacts", []) if a.get("name") == artifact_name]
    checked(len(matches) == 1, f"{artifact_name} artifact missing or duplicated")
    artifact = matches[0]
    size = artifact.get("size_in_bytes")
    checked(artifact.get("expired") is False and isinstance(size, int) and 0 < size <= max_size, f"{artifact_name} artifact expired or oversized")
    digest = artifact.get("digest", "")
    checked(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None, f"{artifact_name} artifact has no SHA-256 digest")
    raw = request_bytes(repo_path(repo, f"actions/artifacts/{artifact['id']}/zip"), max_size)
    checked(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest.removeprefix("sha256:"), f"{artifact_name} artifact digest/size mismatch")
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_bytes(path, max_size):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    checked(bool(token), "read token is required")
    checked(path.startswith("/repos/civitaspo/securefix-server/") and not path.startswith("//"), "binary download path is outside the fixed repository API")
    url = API + path
    opener = urllib.request.build_opener(NoRedirect())
    for redirect in range(5):
        headers = {"Accept": "application/octet-stream", "User-Agent": "securefix-control-bootstrap"}
        if redirect == 0:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        request = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(request, timeout=30) as response:
                raw = response.read(max_size + 1)
                checked(len(raw) <= max_size, "downloaded artifact exceeded limit")
                return raw
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise RuntimeError(f"GitHub binary download returned {error.code}") from error
            location = error.headers.get("Location")
            checked(location is not None and redirect < 4, "binary download redirect limit exceeded")
            target = urllib.parse.urlsplit(urllib.parse.urljoin(url, location))
            host = (target.hostname or "").lower()
            checked(target.scheme == "https" and target.username is None and target.password is None and host and host not in ("localhost", "127.0.0.1", "::1"), "binary download redirect target is unsafe")
            url = target.geturl()
    raise RuntimeError("binary download redirect limit exceeded")


def validate_scratch(repo, source, run_id, policy):
    integration = policy["deployment"]["integration"]
    run = workflow_run(repo, run_id, TEST_WORKFLOW, status="completed")
    checked(run["head_sha"] == source, "generation-one scratch proof must use the exact bootstrap source")
    pair = zip_json_files(artifact_bytes(repo, run_id, "scratch-fixtures", MAX_ARTIFACT), ("state.json", "verification.json"))
    state = pair["state.json"]
    verification = pair["verification.json"]
    checked(state.get("candidate_sha") == source and state.get("repository") == integration["repository"] and state.get("repository_id") == integration["id"] and state.get("workflow_sha") == run["head_sha"], "scratch-fixtures artifact identity mismatch")
    checked(verification.get("version") == 2 and verification.get("repository") == integration["repository"] and verification.get("candidate_sha") == source, "scratch verification does not prove candidate")
    checked(all(isinstance(verification.get(k), int) and verification[k] > 0 for k in ("positive_pr", "stale_pr", "distribution_pr")), "scratch verification PR IDs are invalid")
    checked(re.fullmatch(r"[0-9a-f]{40}", verification.get("merged_sha", "")) is not None and re.fullmatch(r"[0-9a-f]{40}", verification.get("stale_head_sha", "")) is not None, "scratch verification commit identities invalid")
    checked(bool(verification.get("managed_files")) and verification.get("annotated_tag_verified") is True and verification.get("closed_or_merged") is True, "scratch verification evidence incomplete")
    probe = zip_json_files(artifact_bytes(repo, run_id, "control-probe", 16 * 1024), ("control-verification.json",))["control-verification.json"]
    checked(probe.get("version") == 1 and probe.get("repository") == integration["repository"] and probe.get("candidate_sha") == source, "control probe identity mismatch")
    checked(isinstance(probe.get("branch"), str) and probe["branch"].startswith("securefix-integration-control-"), "control probe branch invalid")
    for key in ("base_sha", "generation_one_commit_sha", "generation_two_commit_sha", "generation_three_commit_sha"):
        checked(re.fullmatch(r"[0-9a-f]{40}", probe.get(key, "")) is not None, "control probe commit identity invalid")
    generations = [probe.get(k, "") for k in ("generation_one", "generation_two", "generation_three")]
    checked(all(re.fullmatch(r"[0-9a-f]{64}", x) for x in generations) and len(set(generations)) == 3, "control probe generation identities invalid")
    checked(all(probe.get(k) is True for k in ("source_advance_kept_descriptor", "expected_head_conflict_rejected", "stale_identity_rejected_after_aba")), "control probe CAS evidence incomplete")
    checked(all(probe.get(k) is False for k in ("production_publication_verified", "production_activation_verified", "distribution_verified")), "control probe was not scratch-only")


def validate_proposal(source, verification_run_id, archive_path):
    repo = "civitaspo/securefix-server"
    run_id = int(os.environ.get("GITHUB_RUN_ID", "0"))
    checked(run_id > 0 and os.environ.get("GITHUB_REPOSITORY") == repo and os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_WORKFLOW_REF") == f"{repo}/{BOOTSTRAP_WORKFLOW}@refs/heads/main" and os.environ.get("GITHUB_ACTOR_ID") == str(OWNER_ID) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and os.environ.get("GITHUB_SHA") == source, "proposal is not a first-attempt owner dispatch from current main")
    main = request("GET", repo_path(repo, "commits/main"))
    checked(main.get("sha") == source, "proposal source is not current protected main")
    workflow_run(repo, run_id, BOOTSTRAP_WORKFLOW, source, "in_progress")
    require_absent(repo, source)
    policy, source_policy = current_policy(repo, source)
    required_status(repo, source)
    archive_sha, archived_policy = archive_policy(archive_path)
    checked(archived_policy == source_policy, "published runtime policy differs from exact source policy")
    verify_attestation(archive_path, repo, source, BOOTSTRAP_WORKFLOW)
    validate_scratch(repo, source, verification_run_id, policy)
    return {
        "version": 1,
        "operation": "prepare",
        "repository": repo,
        "repository_id": SERVER_ID,
        "default_branch": "main",
        "owner_id": OWNER_ID,
        "server_bot_id": SERVER_BOT_ID,
        "status_app_id": STATUS_APP_ID,
        "source_sha": source,
        "expected_main_sha": source,
        "archive_sha256": archive_sha,
        "policy_sha256": hashlib.sha256(source_policy).hexdigest(),
        "verification_run_id": int(verification_run_id),
        "publisher_run_id": run_id,
        "descriptor": None,
        "pull_request": None,
        "head_sha": None,
    }


def validate_legacy_scratch_context(source):
    repo = "civitaspo/securefix-server"
    checked(os.environ.get("GITHUB_REPOSITORY") == repo and os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_WORKFLOW_REF") == f"{repo}/{TEST_WORKFLOW}@refs/heads/main" and os.environ.get("GITHUB_ACTOR_ID") == str(OWNER_ID) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and os.environ.get("GITHUB_SHA") == source, "legacy scratch proof is not a first-attempt owner dispatch from current main")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    checked(bool(event_path), "workflow dispatch payload is unavailable")
    with open(event_path, "rb") as event_file:
        event = json.load(event_file)
    checked(event.get("inputs", {}).get("phase") == "bootstrap" and event.get("inputs", {}).get("candidate_sha", "") in ("", source), "legacy scratch phase/source input mismatch")
    main = request("GET", repo_path(repo, "commits/main"))
    checked(main.get("sha") == source, "protected main moved before legacy scratch verification")
    workflow_run(repo, os.environ.get("GITHUB_RUN_ID", "0"), TEST_WORKFLOW, source, "in_progress")
    require_absent(repo, source)
    current_policy(repo, source)
    return {"source_sha": source, "published_runtime_sha": LEGACY_SOURCE_SHA, "published_runtime_tag": LEGACY_TAG}


def validate_dispatch(main_sha, expected_phase):
    repo = "civitaspo/securefix-server"
    checked(os.environ.get("GITHUB_REPOSITORY") == repo and os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_WORKFLOW_REF") == f"{repo}/{BOOTSTRAP_WORKFLOW}@refs/heads/main" and os.environ.get("GITHUB_ACTOR_ID") == str(OWNER_ID) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and os.environ.get("GITHUB_SHA") == main_sha, "operation is not a first-attempt owner dispatch from expected protected main")
    main = request("GET", repo_path(repo, "commits/main"))
    checked(main.get("sha") == main_sha, "protected main moved after dispatch")
    current = workflow_run(repo, os.environ.get("GITHUB_RUN_ID", "0"), BOOTSTRAP_WORKFLOW, main_sha, "in_progress")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        with open(event_path, "rb") as event_file:
            event = json.load(event_file)
        checked(event.get("inputs", {}).get("phase") == expected_phase, "dispatch phase does not match requested operation")
    return repo, current


def validate_review(repo, pr_number, expected_head):
    owner_reviews = []
    for page in range(1, 101):
        reviews = request("GET", repo_path(repo, f"pulls/{pr_number}/reviews?per_page=100&page={page}"))
        owner_reviews.extend(r for r in reviews if r.get("user", {}).get("id") == OWNER_ID)
        if len(reviews) < 100:
            break
    else:
        raise RuntimeError("pull request review pagination exceeded limit")
    checked(bool(owner_reviews), "pull request lacks owner review")
    latest = max(owner_reviews, key=lambda r: r.get("submitted_at", ""))
    checked(latest.get("state") == "APPROVED" and latest.get("commit_id") == expected_head, "latest owner review does not approve exact head")


def validate_pull(repo, pr_number, expected_main, expected_head, bootstrap):
    pull = request("GET", repo_path(repo, f"pulls/{pr_number}"))
    checked(pull.get("state") == "open" and pull.get("head", {}).get("sha") == expected_head and pull.get("base", {}).get("ref") == "main" and pull.get("base", {}).get("sha") == expected_main and pull.get("base", {}).get("repo", {}).get("full_name") == repo and pull.get("head", {}).get("repo", {}).get("full_name") == repo, "pull request identity is invalid")
    if bootstrap:
        checked(pull.get("user", {}).get("id") == SERVER_BOT_ID, "bootstrap descriptor PR is not authored by the configured Server App")
        descriptor = json.loads(contents(repo, ACTIVE, expected_head))
        checked(pull.get("head", {}).get("ref") == f"securefix-control-bootstrap-{descriptor.get('source_sha', '')[:12]}", "bootstrap PR branch is invalid")
        files = request("GET", repo_path(repo, f"pulls/{pr_number}/files?per_page=100"))
        checked(pull.get("changed_files") == 1 and len(files) == 1 and files[0].get("filename") == ACTIVE, "bootstrap PR must change only active descriptor")
    else:
        checked(pull.get("user", {}).get("id") == SERVER_BOT_ID, "repair PR must be authored by the configured Server App")
        files = request("GET", repo_path(repo, f"pulls/{pr_number}/files?per_page=100"))
        forbidden = {ACTIVE, BOOTSTRAP_WORKFLOW, "scripts/control-bootstrap.py"}
        checked(pull.get("changed_files", 0) == len(files) and bool(files) and not any(f.get("filename") in forbidden for f in files), "repair PR is empty, truncated, or changes active descriptor/bootstrap authority")
    validate_review(repo, pr_number, expected_head)
    required_status(repo, expected_head)
    return pull


def validate_bootstrap_merge(pr_number, expected_main, expected_head, control_id):
    checked(re.fullmatch(r"[0-9a-f]{64}", control_id) is not None, "invalid control identity")
    repo, current_run = validate_dispatch(expected_main, "merge")
    require_absent(repo, expected_main)
    policy, _ = current_policy(repo, expected_main)
    pull = validate_pull(repo, pr_number, expected_main, expected_head, True)
    descriptor_bytes = contents(repo, ACTIVE, expected_head)
    descriptor = json.loads(descriptor_bytes)
    fields = ("version", "generation", "source_sha", "policy_sha256", "archive_sha256", "release_id", "asset_id", "publisher_run_id", "verification_run_id", "previous")
    checked(set(descriptor) == set(fields) and descriptor.get("version") == 1 and descriptor.get("generation") == 1 and descriptor.get("previous") == ZERO, "descriptor is not strict generation one")
    identity = canonical_control_id(descriptor)
    checked(identity == control_id, "bootstrap descriptor identity mismatch")
    source = descriptor["source_sha"]
    checked(re.fullmatch(r"[0-9a-f]{40}", source) is not None, "invalid descriptor source SHA")
    checked(source == expected_main, "generation-one descriptor source differs from expected current main")
    checked(
        type(descriptor["version"]) is int and descriptor["version"] == 1
        and type(descriptor["generation"]) is int and descriptor["generation"] == 1
        and all(type(descriptor[k]) is int and descriptor[k] > 0 for k in ("release_id", "asset_id", "publisher_run_id", "verification_run_id"))
        and re.fullmatch(r"[0-9a-f]{64}", descriptor["policy_sha256"]) is not None
        and re.fullmatch(r"[0-9a-f]{64}", descriptor["archive_sha256"]) is not None,
        "descriptor contains invalid release, run, or digest identities",
    )
    descriptor_commit = request("GET", repo_path(repo, f"commits/{expected_head}"))
    checked(descriptor_commit.get("sha") == expected_head and descriptor_commit.get("commit", {}).get("verification", {}).get("verified") is True, "bootstrap descriptor commit is not verified")
    required_status(repo, source)
    publication_run = workflow_run(repo, descriptor["publisher_run_id"], BOOTSTRAP_WORKFLOW, source)
    version_bytes = contents(repo, "Cargo.toml", source)
    manifest = version_bytes.decode("utf-8")
    match = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"\s*$", manifest)
    checked(match is not None, "source version is missing")
    tag = "v" + match.group(1)
    ref = request("GET", repo_path(repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"))
    checked(ref.get("object", {}).get("type") == "commit" and ref.get("object", {}).get("sha") == source, "published runtime tag does not point to descriptor source")
    release = request("GET", repo_path(repo, f"releases/{descriptor['release_id']}"))
    checked(release.get("id") == descriptor["release_id"] and release.get("tag_name") == tag and release.get("target_commitish") == source and release.get("draft") is False and release.get("immutable") is True, "bootstrap release metadata is invalid or mutable")
    assets = release.get("assets", [])
    checked(len(assets) == 1 and assets[0].get("id") == descriptor["asset_id"] and assets[0].get("name") == ASSET and assets[0].get("state") == "uploaded", "bootstrap release asset identity mismatch")
    download = request_bytes(repo_path(repo, f"releases/assets/{assets[0]['id']}"), MAX_ARCHIVE)
    with tempfile.NamedTemporaryFile() as archive_file:
        archive_file.write(download)
        archive_file.flush()
        digest, archived_policy = archive_policy(archive_file.name)
        checked(digest == descriptor["archive_sha256"] == assets[0].get("digest", "").removeprefix("sha256:") and len(download) == assets[0].get("size"), "bootstrap archive digest/size mismatch")
        source_policy = contents(repo, "policy.json", source)
        checked(archived_policy == source_policy and hashlib.sha256(source_policy).hexdigest() == descriptor["policy_sha256"] and source_policy == open("policy.json", "rb").read(), "published policy differs from source/trusted policy")
        verify_attestation(archive_file.name, repo, source, BOOTSTRAP_WORKFLOW)
    validate_scratch(repo, source, descriptor["verification_run_id"], policy)
    checked(pull.get("head", {}).get("sha") == expected_head, "bootstrap PR head moved")
    return {"version": 1, "operation": "merge", "repository": repo, "expected_main_sha": expected_main, "expected_head_sha": expected_head, "pull_request": pr_number, "control_id": identity, "descriptor": descriptor}


def validate_repair_commit(expected_main, expected_head, pr_number=None, phase="repair-propose"):
    repo, current_run = validate_dispatch(expected_main, phase)
    require_absent(repo, expected_main)
    current_policy(repo, expected_main)
    checked(re.fullmatch(r"[0-9a-f]{40}", expected_head) is not None, "invalid repair head SHA")
    compare = request("GET", repo_path(repo, f"compare/{expected_main}...{expected_head}"))
    commits = compare.get("commits", [])
    checked(compare.get("base_commit", {}).get("sha") == expected_main and compare.get("merge_base_commit", {}).get("sha") == expected_main and compare.get("status") == "ahead" and commits and all(c.get("commit", {}).get("verification", {}).get("verified") is True for c in commits), "repair head is not a signed descendant of expected main")
    changed = compare.get("files", [])
    forbidden = {ACTIVE, BOOTSTRAP_WORKFLOW, "scripts/control-bootstrap.py"}
    checked(bool(changed) and len(changed) < 300 and not any(f.get("filename") in forbidden for f in changed), "repair head is empty, too large to qualify, or changes active descriptor/bootstrap authority")
    required_status(repo, expected_head)
    if pr_number is None:
        branches = request("GET", repo_path(repo, f"commits/{expected_head}/branches-where-head"))
        checked(isinstance(branches, list), "repair branch response is invalid")
        branch_names = [b.get("name") for b in branches if b.get("name")]
        checked(bool(branch_names), "repair head is not on a repository branch")
        prs = [pr for branch in branch_names for pr in request("GET", repo_path(repo, f"pulls?state=open&head=civitaspo:{urllib.parse.quote(branch, safe='')}&base=main"))]
        checked(not prs, "repair head already has a pull request")
        return {"version": 1, "operation": "repair-propose", "repository": repo, "branch": branch_names[0], "expected_main_sha": expected_main, "expected_head_sha": expected_head}
    pull = validate_pull(repo, pr_number, expected_main, expected_head, False)
    return {"version": 1, "operation": "repair-merge", "repository": repo, "expected_main_sha": expected_main, "expected_head_sha": expected_head, "pull_request": pr_number}


def create_repair_pr(expected_main, expected_head):
    plan = validate_repair_commit(expected_main, expected_head)
    require_server_installation(plan["repository"])
    branches = request("GET", repo_path(plan["repository"], f"commits/{expected_head}/branches-where-head"))
    checked(isinstance(branches, list), "repair branch response is invalid")
    branch = next((b.get("name") for b in branches if b.get("name") == plan["branch"]), None)
    checked(branch is not None, "repair head is not on a branch")
    pull = request("POST", repo_path(plan["repository"], "pulls"), {"head": branch, "base": "main", "title": "Repair Securefix bootstrap candidate", "body": f"Repair candidate source while the active descriptor is absent.\n\nExpected main: {expected_main}\nRepair head: {expected_head}"})
    checked(pull.get("head", {}).get("sha") == expected_head and pull.get("user", {}).get("id") == SERVER_BOT_ID, "Server App repair PR identity mismatch")
    print(json.dumps({"pull_request": pull["number"], "head_sha": expected_head}))


def resume_descriptor_branch(repo, branch, expected_main, descriptor):
    ref_path = repo_path(repo, f"git/ref/heads/{urllib.parse.quote(branch, safe='')}")
    ref = request("GET", ref_path, allow_missing=True)
    if ref is None:
        return None, None, False
    head = ref.get("object", {}).get("sha")
    checked(re.fullmatch(r"[0-9a-f]{40}", head or "") is not None, "reserved bootstrap branch has an invalid head")
    compare = request("GET", repo_path(repo, f"compare/{expected_main}...{head}"))
    commits = compare.get("commits", [])
    files = compare.get("files", [])
    checked(
        compare.get("base_commit", {}).get("sha") == expected_main
        and compare.get("merge_base_commit", {}).get("sha") == expected_main
        and compare.get("status") == "ahead"
        and commits
        and all(c.get("commit", {}).get("verification", {}).get("verified") is True for c in commits)
        and len(files) == 1
        and files[0].get("filename") == ACTIVE,
        "reserved bootstrap branch is not a signed descriptor-only descendant of expected main",
    )
    stored = json.loads(contents(repo, ACTIVE, head))
    checked(
        set(stored) == set(descriptor)
        and type(stored.get("publisher_run_id")) is int
        and stored["publisher_run_id"] > 0
        and {k: v for k, v in stored.items() if k != "publisher_run_id"}
        == {k: v for k, v in descriptor.items() if k != "publisher_run_id"},
        "reserved bootstrap descriptor differs beyond its prior publisher run identity",
    )
    prs = request("GET", repo_path(repo, f"pulls?state=all&head={urllib.parse.quote('civitaspo:' + branch, safe='')}&base=main"))
    checked(len(prs) <= 1, "reserved bootstrap branch has multiple pull requests")
    pull = prs[0] if prs else None
    if pull:
        checked(
            pull.get("user", {}).get("id") == SERVER_BOT_ID
            and pull.get("head", {}).get("ref") == branch
            and pull.get("head", {}).get("sha") == head
            and pull.get("head", {}).get("repo", {}).get("full_name") == repo
            and pull.get("base", {}).get("ref") == "main"
            and pull.get("base", {}).get("sha") == expected_main
            and pull.get("base", {}).get("repo", {}).get("full_name") == repo
            and pull.get("merged_at") is None,
            "reserved bootstrap pull request identity is invalid",
        )
    if stored != descriptor:
        checked(current_main(repo, "main") == expected_main, "protected main moved before bootstrap retry")
        require_absent(repo, expected_main)
        mutation = """mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }"""
        result = request("POST", "/graphql", {
            "query": mutation,
            "variables": {"input": {
                "branch": {"repositoryNameWithOwner": repo, "branchName": branch},
                "expectedHeadOid": head,
                "message": {"headline": "chore: refresh bootstrap publisher evidence"},
                "fileChanges": {"additions": [{"path": ACTIVE, "contents": base64.b64encode((json.dumps(descriptor, indent=2) + "\n").encode()).decode()}]},
            }},
        })
        new_head = result.get("data", {}).get("createCommitOnBranch", {}).get("commit", {}).get("oid")
        checked(re.fullmatch(r"[0-9a-f]{40}", new_head or "") is not None and new_head != head, "bootstrap retry did not create a new compare-and-swap head")
        head = new_head
    if pull:
        if pull.get("state") != "open":
            pull = request("PATCH", repo_path(repo, f"pulls/{pull['number']}"), {"state": "open"})
        pull = request("GET", repo_path(repo, f"pulls/{pull['number']}"))
        checked(pull.get("state") == "open" and pull.get("head", {}).get("sha") == head, "resumed bootstrap PR did not move to the refreshed descriptor head")
    return head, pull, True


def request(method, path, body=None, content_type="application/json", allow_missing=False, token=None):
    if token is None:
        token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")) if method in ("GET", "HEAD") else os.environ.get("GH_TOKEN", "")
    if not token:
        raise RuntimeError("GH_TOKEN is required")
    data = body
    if isinstance(body, (dict, list)):
        data = json.dumps(body, separators=(",", ":")).encode()
    elif isinstance(body, str):
        data = body.encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "securefix-control-bootstrap",
    }
    if data is not None:
        headers["Content-Type"] = content_type
    if path.startswith("https://"):
        checked(path.startswith("https://uploads.github.com/repos/civitaspo/securefix-server/releases/"), "upload URL is outside the fixed GitHub upload host/repository")
        url = path
    else:
        url = API + path
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = response.read(32 * 1024 * 1024 + 1)
            if len(payload) > 32 * 1024 * 1024:
                raise RuntimeError("GitHub response exceeded size limit")
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        if allow_missing and error.code == 404:
            return None
        detail = error.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {method} {path} returned {error.code}: {detail}") from error


def repo_path(repo, suffix):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise RuntimeError("invalid repository name")
    return f"/repos/{repo}/{suffix}"


def read_plan(path):
    with open(path, "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("bootstrap plan is oversized")
    plan = json.loads(raw)
    required = {
        "version", "operation", "repository", "repository_id", "default_branch", "owner_id",
        "server_bot_id", "status_app_id", "source_sha", "expected_main_sha",
        "archive_sha256", "policy_sha256", "verification_run_id", "publisher_run_id",
        "descriptor", "pull_request", "head_sha",
    }
    if set(plan) != required or plan["version"] != 1:
        raise RuntimeError("bootstrap plan schema mismatch")
    for key in ("source_sha", "expected_main_sha"):
        if not re.fullmatch(r"[0-9a-f]{40}", plan[key]):
            raise RuntimeError(f"invalid {key}")
    for key in ("archive_sha256", "policy_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", plan[key]):
            raise RuntimeError(f"invalid {key}")
    if plan["repository"] != "civitaspo/securefix-server":
        raise RuntimeError("unexpected repository")
    return plan


def current_main(repo, branch):
    commit = request("GET", repo_path(repo, f"commits/{urllib.parse.quote(branch, safe='')}"))
    return commit.get("sha")


def require_absent(repo, revision):
    path = repo_path(repo, f"contents/{ACTIVE}?ref={urllib.parse.quote(revision, safe='')}")
    if request("GET", path, allow_missing=True) is not None:
        raise RuntimeError("active descriptor exists; bootstrap is permanently disabled")


def require_server_installation(repo):
    value = request("GET", "/installation/repositories?per_page=100", token=os.environ.get("GH_TOKEN"))
    items = value.get("repositories", [])
    if value.get("total_count") != 1 or len(items) != 1 or items[0].get("full_name") != repo or items[0].get("id") != 1250079425:
        raise RuntimeError("Server App token must be installed only on the configured server repository")


def create_descriptor_pr(plan, archive_path):
    repo = plan["repository"]
    if plan["operation"] != "prepare":
        raise RuntimeError("proposal requires a prepare plan")
    actual_plan = validate_proposal(plan["source_sha"], plan["verification_run_id"], archive_path)
    checked(plan == actual_plan, "bootstrap plan differs from fixed trusted revalidation")
    require_server_installation(repo)
    if current_main(repo, plan["default_branch"]) != plan["expected_main_sha"]:
        raise RuntimeError("protected main moved after read-only validation")
    require_absent(repo, plan["expected_main_sha"])
    with open(archive_path, "rb") as stream:
        archive = stream.read(128 * 1024 * 1024 + 1)
    if len(archive) > 128 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != plan["archive_sha256"]:
        raise RuntimeError("candidate archive differs from validated plan")

    source = plan["source_sha"]
    source_policy = contents(repo, "policy.json", source)
    checked(source_policy == open("policy.json", "rb").read(), "source policy differs from trusted bootstrap policy")
    version = request("GET", repo_path(repo, f"contents/Cargo.toml?ref={source}"))
    manifest = base64.b64decode(version["content"], validate=False).decode("utf-8")
    match = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"\s*$", manifest)
    if not match:
        raise RuntimeError("source Cargo.toml has no simple package version")
    tag = "v" + match.group(1)
    tag_ref_path = repo_path(repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}")
    tag_ref = request("GET", tag_ref_path, allow_missing=True)
    if tag_ref is None:
        request("POST", repo_path(repo, "git/refs"), {"ref": f"refs/tags/{tag}", "sha": source})
    elif tag_ref.get("object", {}).get("type") != "commit" or tag_ref.get("object", {}).get("sha") != source:
        raise RuntimeError("runtime tag is reserved for another source")
    release_path = repo_path(repo, f"releases/tags/{urllib.parse.quote(tag, safe='')}")
    release = request("GET", release_path, allow_missing=True)
    if release is None:
        release = request("POST", repo_path(repo, "releases"), {
            "tag_name": tag,
            "name": tag,
            "target_commitish": source,
            "draft": True,
            "prerelease": "-" in match.group(1),
            "make_latest": "false",
            "generate_release_notes": False,
        })
    if release.get("tag_name") != tag or release.get("target_commitish") != source or release.get("draft") not in (True, False):
        raise RuntimeError("reserved release identity differs from candidate")
    existing_assets = release.get("assets", [])
    if len(existing_assets) > 1:
        raise RuntimeError("reserved release contains unexpected assets")
    archive_sha256 = plan["archive_sha256"]
    if release.get("immutable") is True:
        archive_sha256 = verify_published_immutable_archive(repo, release, source, source_policy)
    elif existing_assets:
        existing = existing_assets[0]
        if existing.get("name") != ASSET or existing.get("size") != len(archive) or existing.get("digest") != "sha256:" + plan["archive_sha256"]:
            raise RuntimeError("reserved release asset differs from validated candidate")
    upload = release["upload_url"].split("{", 1)[0] + "?name=" + urllib.parse.quote(ASSET)
    if not existing_assets:
        request("POST", upload, archive, "application/gzip")
    if release.get("draft") is True:
        release = request("PATCH", repo_path(repo, f"releases/{release['id']}"), {"draft": False})
    release = request("GET", repo_path(repo, f"releases/{release['id']}"))
    if release.get("immutable") is not True or len(release.get("assets", [])) != 1:
        raise RuntimeError("published runtime release is not immutable or has unexpected assets")
    asset = release["assets"][0]
    if asset.get("name") != ASSET or asset.get("digest") != "sha256:" + archive_sha256:
        raise RuntimeError("published runtime asset metadata differs from the verified archive")
    if archive_sha256 == plan["archive_sha256"] and asset.get("size") != len(archive):
        raise RuntimeError("published runtime asset size differs from validated candidate")

    descriptor = {
        "version": 1,
        "generation": 1,
        "source_sha": source,
        "policy_sha256": plan["policy_sha256"],
        "archive_sha256": archive_sha256,
        "release_id": release["id"],
        "asset_id": asset["id"],
        "publisher_run_id": plan["publisher_run_id"],
        "verification_run_id": plan["verification_run_id"],
        "previous": ZERO,
    }
    branch = f"securefix-control-bootstrap-{source[:12]}"
    if current_main(repo, plan["default_branch"]) != plan["expected_main_sha"]:
        raise RuntimeError("protected main moved before bootstrap descriptor write")
    require_absent(repo, plan["expected_main_sha"])
    branch_head, existing_pr, branch_exists = resume_descriptor_branch(repo, branch, plan["expected_main_sha"], descriptor)
    if existing_pr:
        print(json.dumps({"pull_request": existing_pr["number"], "head_sha": branch_head, "control_id": canonical_control_id(descriptor)}))
        return
    branch_ref_path = repo_path(repo, f"git/ref/heads/{branch}")
    if not branch_exists:
        branch_ref = request("GET", branch_ref_path, allow_missing=True)
        if branch_ref is not None:
            raise RuntimeError("reserved bootstrap branch appeared during creation")
        request("POST", repo_path(repo, "git/refs"), {"ref": f"refs/heads/{branch}", "sha": plan["expected_main_sha"]})
        branch_head = plan["expected_main_sha"]
        mutation = """mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }"""
        result = request("POST", "/graphql", {
            "query": mutation,
            "variables": {"input": {
                "branch": {"repositoryNameWithOwner": repo, "branchName": branch},
                "expectedHeadOid": branch_head,
                "message": {"headline": "chore: bootstrap active Securefix control revision"},
                "fileChanges": {"additions": [{"path": ACTIVE, "contents": base64.b64encode((json.dumps(descriptor, indent=2) + "\n").encode()).decode()}]},
            }},
        })
        branch_head = result["data"]["createCommitOnBranch"]["commit"]["oid"]
    head = branch_head
    pull = request("POST", repo_path(repo, "pulls"), {
        "head": branch,
        "base": plan["default_branch"],
        "title": "Bootstrap active control descriptor",
        "body": "Create the first active control descriptor after independent validation.\n\nSource: " + source,
        "draft": False,
    })
    if pull.get("head", {}).get("sha") != head or pull.get("user", {}).get("id") != plan["server_bot_id"]:
        raise RuntimeError("bootstrap pull request identity mismatch")
    print(json.dumps({"pull_request": pull["number"], "head_sha": head, "control_id": canonical_control_id(descriptor)}))


def merge_bootstrap(repo, pr_number, expected_main, expected_head, control_id):
    if repo != "civitaspo/securefix-server":
        raise RuntimeError("unexpected repository")
    validate_bootstrap_merge(pr_number, expected_main, expected_head, control_id)
    require_server_installation(repo)
    result = request("PUT", repo_path(repo, f"pulls/{pr_number}/merge"), {"sha": expected_head, "merge_method": "squash"})
    if result.get("merged") is not True:
        raise RuntimeError("GitHub did not merge the reviewed bootstrap PR")


def write_plan(plan):
    value = json.dumps(plan, separators=(",", ":"))
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"plan<<securefix_repair_plan\n{value}\nsecurefix_repair_plan\n")
    else:
        print(value)


def merge_repair(repo, pr_number, expected_main, expected_head):
    require_server_installation(repo)
    checked(repo == "civitaspo/securefix-server", "unexpected repository")
    validate_repair_commit(expected_main, expected_head, pr_number, "repair-merge")
    result = request("PUT", repo_path(repo, f"pulls/{pr_number}/merge"), {"sha": expected_head, "merge_method": "squash"})
    if result.get("merged") is not True:
        raise RuntimeError("GitHub did not merge the reviewed repair PR")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    propose = sub.add_parser("propose")
    propose.add_argument("--plan", required=True)
    propose.add_argument("--archive", required=True)
    merge = sub.add_parser("merge")
    merge.add_argument("--repository", required=True)
    merge.add_argument("--pull-request", required=True, type=int)
    merge.add_argument("--expected-main-sha", required=True)
    merge.add_argument("--expected-head-sha", required=True)
    merge.add_argument("--control-id", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--source-sha", required=True)
    prepare.add_argument("--verification-run-id", required=True, type=int)
    prepare.add_argument("--archive", required=True)
    validate_merge = sub.add_parser("validate-merge")
    validate_merge.add_argument("--pull-request", required=True, type=int)
    validate_merge.add_argument("--expected-main-sha", required=True)
    validate_merge.add_argument("--expected-head-sha", required=True)
    validate_merge.add_argument("--control-id", required=True)
    repair_propose = sub.add_parser("repair-propose")
    repair_propose.add_argument("--expected-main-sha", required=True)
    repair_propose.add_argument("--expected-head-sha", required=True)
    legacy_context = sub.add_parser("validate-legacy-context")
    legacy_context.add_argument("--source-sha", required=True)
    repair_merge = sub.add_parser("repair-merge")
    repair_merge.add_argument("--repository", required=True)
    repair_merge.add_argument("--pull-request", required=True, type=int)
    repair_merge.add_argument("--expected-main-sha", required=True)
    repair_merge.add_argument("--expected-head-sha", required=True)
    args = parser.parse_args()
    try:
        if args.command == "propose":
            create_descriptor_pr(read_plan(args.plan), args.archive)
        elif args.command == "merge":
            merge_bootstrap(args.repository, args.pull_request, args.expected_main_sha, args.expected_head_sha, args.control_id)
        elif args.command == "prepare":
            write_plan(validate_proposal(args.source_sha, args.verification_run_id, args.archive))
        elif args.command == "validate-merge":
            write_plan(validate_bootstrap_merge(args.pull_request, args.expected_main_sha, args.expected_head_sha, args.control_id))
        elif args.command == "repair-propose":
            plan = validate_repair_commit(args.expected_main_sha, args.expected_head_sha, phase="repair-propose")
            require_server_installation(plan["repository"])
            create_repair_pr(args.expected_main_sha, args.expected_head_sha)
        elif args.command == "validate-legacy-context":
            write_plan(validate_legacy_scratch_context(args.source_sha))
        elif args.command == "repair-merge":
            merge_repair(args.repository, args.pull_request, args.expected_main_sha, args.expected_head_sha)
        else:
            parser.error("unknown command")
    except (KeyError, ValueError, OSError, RuntimeError, urllib.error.URLError) as error:
        print(f"control bootstrap failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
