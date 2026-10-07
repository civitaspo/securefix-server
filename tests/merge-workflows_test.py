import json
import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def workflow_command(workflow, name):
    source = (ROOT / ".github/workflows" / workflow).read_text()
    step = source.split(f"      - name: {name}\n", 1)[1]
    step = step.split("\n      - name:", 1)[0]
    match = re.search(r"^( +)run: \|\n", step, re.MULTILINE)
    if match is None:
        raise AssertionError(f"No shell command for {name}")
    indent = len(match[1]) + 2
    lines = []
    for line in step[match.end():].splitlines():
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        lines.append(line[indent:])
    return "\n".join(lines)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.event = {
            "repository": {"id": 5, "owner": {"login": "civitaspo"},
                           "name": "example", "full_name": "civitaspo/example"},
            "issue": {"number": 7, "pull_request": {}},
            "comment": {"id": 11, "body": "/merge", "user": {"id": 4525500}},
        }
        self.pr = {"number": 7, "state": "open", "draft": False,
                   "head": {"sha": SHA, "repo": {"full_name": "civitaspo/example"}},
                   "base": {"ref": "main", "repo": {"full_name": "civitaspo/example"}}}
        self.repository = {**self.event["repository"], "default_branch": "main"}
        self.comment = {**self.event["comment"], "updated_at": "2026-01-01T00:00:00Z",
                        "issue_url": "https://api.github.com/repos/civitaspo/example/issues/7"}
        self.responses = {
            "repos/civitaspo/example/pulls/7": self.pr,
            "repos/civitaspo/example": self.repository,
            "repos/civitaspo/example/issues/comments/11": self.comment,
            "repos/civitaspo/securefix-server/labels": {},
        }
        fake_gh = self.bin / "gh"
        fake_gh.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['GH_CALLS']).open('a') as calls:
    calls.write(json.dumps(args) + '\\n')
if '--input' in args:
    Path(os.environ['GH_PAYLOAD']).write_text(sys.stdin.read())
responses = json.loads(Path(os.environ['GH_RESPONSES']).read_text())
endpoint = next((arg.lstrip('/') for arg in args if arg.lstrip('/').startswith('repos/')), '')
endpoint = endpoint.split('?')[0]
if 'graphql' in args:
    endpoint = 'graphql'
if endpoint not in responses:
    print('Unexpected API endpoint: ' + endpoint, file=sys.stderr)
    sys.exit(1)
response = responses[endpoint]
if isinstance(response, dict) and '_error' in response:
    print('gh: ' + response['_error'] + ' (HTTP ' + str(response.get('_status', 404)) + ')', file=sys.stderr)
    sys.exit(1)
if isinstance(response, dict) and '_pages' in response:
    for page in response['_pages']:
        print(json.dumps(page))
else:
    print(json.dumps(response))
""")
        fake_gh.chmod(0o700)
        fake_sleep = self.bin / "sleep"
        fake_sleep.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$SLEEP_CALL"\nexit 1\n')
        fake_sleep.chmod(0o700)
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "GH_TOKEN": "fixture-token",
            "GITHUB_EVENT_PATH": str(self.directory / "event.json"),
            "GITHUB_REPOSITORY": "civitaspo/example",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_SHA": "c" * 40,
            "GITHUB_RUN_ID": "9",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKSPACE": str(self.directory),
            "GITHUB_OUTPUT": str(self.directory / "outputs"),
            "GITHUB_STEP_SUMMARY": str(self.directory / "summary"),
            "GH_RESPONSES": str(self.directory / "responses.json"),
            "GH_CALLS": str(self.directory / "calls.jsonl"),
            "GH_PAYLOAD": str(self.directory / "payload.json"),
            "RUNNER_TEMP": str(self.directory),
            "SLEEP_CALL": str(self.directory / "sleep-call"),
        }

    def run_step(self, workflow, name, **env):
        Path(self.env["GITHUB_EVENT_PATH"]).write_text(json.dumps(self.event))
        Path(self.env["GH_RESPONSES"]).write_text(json.dumps(self.responses))
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", workflow_command(workflow, name)],
            cwd=self.directory, env={**self.env, **env}, text=True,
            capture_output=True, timeout=10,
        )

    def capture(self):
        return self.run_step("reusable-merge-request.yml", "Capture the merge request")

    def test_capture_records_original_head_and_comment(self):
        result = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.directory / "merge-request/manifest.json").read_text())
        self.assertEqual(manifest["pullRequest"], {"number": 7, "headSha": SHA, "baseRef": "main"})
        self.assertEqual(manifest["repository"], {"id": 5, "fullName": "civitaspo/example"})
        self.assertEqual(manifest["comment"], {"id": 11, "authorId": 4525500,
                                              "updatedAt": "2026-01-01T00:00:00Z"})
        self.assertEqual((self.directory / "outputs").read_text(), "repository=example\nrun_id=9\n")

    def test_capture_rejects_unauthorized_or_changed_request(self):
        for change in ["author", "body", "draft", "base", "closed", "deleted"]:
            with self.subTest(change=change):
                pr = self.responses["repos/civitaspo/example/pulls/7"]
                comment = self.responses["repos/civitaspo/example/issues/comments/11"]
                original_pr, original_comment = dict(pr), dict(comment)
                if change == "author":
                    self.event["comment"]["user"] = {"id": 1}
                elif change == "body":
                    comment["body"] = "/merge edited"
                elif change == "draft":
                    pr["draft"] = True
                elif change == "base":
                    pr["base"] = {"ref": "other"}
                elif change == "closed":
                    pr["state"] = "closed"
                else:
                    self.responses["repos/civitaspo/example/issues/comments/11"] = {"_error": "Not Found"}
                self.assertNotEqual(self.capture().returncode, 0)
                self.assertFalse((self.directory / "merge-request/manifest.json").exists())
                self.event["comment"]["user"] = {"id": 4525500}
                self.responses["repos/civitaspo/example/pulls/7"] = original_pr
                self.responses["repos/civitaspo/example/issues/comments/11"] = original_comment

    def test_label_contains_only_source_run_locator(self):
        result = self.run_step("reusable-merge-request.yml", "Notify Securefix Server",
                               SERVER_REPOSITORY="securefix-server",
                               SOURCE_REPOSITORY="civitaspo/example", SOURCE_RUN_ID="9")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["api", "--method", "POST", "repos/civitaspo/securefix-server/labels",
                                 "-f", "name=merge-request-9", "-f", "color=1f6feb",
                                 "-f", "description=civitaspo/example/9"]])
        self.assertIn("Request 9 for civitaspo/example", (self.directory / "summary").read_text())

    def locator(self, **changes):
        settings = self.directory / "repo-settings"
        settings.mkdir(exist_ok=True)
        (settings / "allowlist.json").write_text('["example"]')
        env = {"LABEL_NAME": "merge-request-9", "LABEL_DESCRIPTION": "civitaspo/example/9",
               "SENDER_ID": "288068203", "SENDER_TYPE": "Bot", "RUN_ATTEMPT": "1",
               "VERIFICATION_REPOSITORY": "", **changes}
        return self.run_step("merge.yml", "Resolve the source run locator", **env)

    def test_locator_accepts_only_authenticated_allowlisted_source(self):
        result = self.locator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "outputs").read_text(),
                         "repository=civitaspo/example\nrepository_name=example\nrun_id=9\n")
        for changes in [{"SENDER_ID": "1"}, {"SENDER_TYPE": "User"}, {"RUN_ATTEMPT": "2"},
                        {"LABEL_NAME": "merge-request-8"},
                        {"LABEL_DESCRIPTION": "civitaspo/unlisted/9"},
                        {"LABEL_DESCRIPTION": "attacker/example/9"}]:
            with self.subTest(changes=changes):
                self.assertNotEqual(self.locator(**changes).returncode, 0)

    def manifest(self, **changes):
        manifest = {
            "version": 1, "repository": {"id": 5, "fullName": "civitaspo/example"},
            "pullRequest": {"number": 7, "headSha": SHA, "baseRef": "main"},
            "comment": {"id": 11, "authorId": 4525500, "updatedAt": self.comment["updated_at"]},
            "acceptedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "runId": 9, "runAttempt": 1, "workflowSha": "c" * 40, **changes,
        }
        path = self.directory / "manifest.json"
        path.write_text(json.dumps(manifest))
        self.responses["repos/civitaspo/example/issues/7/comments"] = []
        self.responses["repos/civitaspo/example/issues/7/timeline"] = []
        return path, manifest

    def validate(self, path):
        return self.run_step("merge.yml", "Validate the request record and current pull request",
                             SOURCE_REPOSITORY="civitaspo/example", SOURCE_RUN_ID="9",
                             SOURCE_HEAD_SHA="c" * 40, MANIFEST_PATH=str(path))

    def test_manifest_accepts_original_millisecond_timestamp(self):
        path, manifest = self.manifest()
        result = self.validate(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = (self.directory / "outputs").read_text().splitlines()
        record = next(line[len("manifest="):] for line in outputs if line.startswith("manifest="))
        self.assertEqual(json.loads(record), manifest)

    def test_manifest_rejects_unknown_expired_and_changed_requests(self):
        for changes in [{"version": 2}, {"runAttempt": 2}, {"runId": 10},
                        {"acceptedAt": "2020-01-01T00:00:00Z"},
                        {"acceptedAt": "2099-01-01T00:00:00Z"},
                        {"repository": {"id": 5.5, "fullName": "civitaspo/example"}},
                        {"pullRequest": {"number": 7.5, "headSha": SHA, "baseRef": "main"}},
                        {"workflowSha": "d" * 40}]:
            with self.subTest(changes=changes):
                path, _ = self.manifest(**changes)
                result = self.validate(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid fields", result.stderr)
        path, _ = self.manifest()
        self.pr["head"]["sha"] = "b" * 40
        self.assertNotEqual(self.validate(path).returncode, 0)

    def test_terminal_marker_requires_server_identity_and_checks_all_pages(self):
        path, _ = self.manifest()
        marker = "<!-- securefix-merge-request:9 -->"
        self.responses["repos/civitaspo/example/issues/7/comments"] = {
            "_pages": [[{"user": {"id": 1}, "body": marker}], []]}
        self.assertEqual(self.validate(path).returncode, 0)
        self.responses["repos/civitaspo/example/issues/7/comments"] = {
            "_pages": [[{"user": {"id": 288069019}, "body": marker}], []]}
        self.assertNotEqual(self.validate(path).returncode, 0)

    def test_timeline_rejects_same_second_force_push_and_close_restore(self):
        for event in ["head_ref_force_pushed", "head_ref_deleted", "base_ref_changed",
                      "closed", "reopened", "convert_to_draft", "ready_for_review"]:
            with self.subTest(event=event):
                path, manifest = self.manifest()
                self.responses["repos/civitaspo/example/issues/7/timeline"] = [
                    {"event": event, "created_at": manifest["acceptedAt"].split('.')[0] + "Z"}]
                self.assertNotEqual(self.validate(path).returncode, 0)

    def test_timeline_parse_failure_never_allows_merge(self):
        path, _ = self.manifest()
        for event in [{"event": "head_ref_force_pushed", "created_at": "not-a-date"},
                      {"event": "head_ref_force_pushed"}]:
            with self.subTest(event=event):
                self.responses["repos/civitaspo/example/issues/7/timeline"] = [event]
                self.assertNotEqual(self.validate(path).returncode, 0)

    def source(self):
        pin = "b" * 40
        prefix = "civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@"
        run = {
            "id": 9, "status": "completed", "conclusion": "success", "run_attempt": 1,
            "event": "issue_comment", "repository": {"full_name": "civitaspo/example"},
            "workflow_id": 3, "path": ".github/workflows/merge-request.yml@refs/heads/main",
            "head_branch": "main", "head_sha": "c" * 40,
            "referenced_workflows": [{"path": prefix + pin, "sha": pin}],
        }
        self.responses.update({
            "repos/civitaspo/example/actions/runs/9": run,
            "repos/civitaspo/example/actions/workflows/3": {"path": ".github/workflows/merge-request.yml"},
            "repos/civitaspo/example/compare/" + "c" * 40 + "...main": {"status": "ahead"},
            "repos/civitaspo/example/contents/.github/workflows/merge-request.yml": {
                "encoding": "base64", "content": base64.b64encode(
                    ("uses: " + prefix + pin + " # v0.2.0-rc.1\n").encode()).decode()},
            "repos/civitaspo/securefix-server": {"default_branch": "main"},
            "repos/civitaspo/securefix-server/compare/" + pin + "...main": {"status": "ahead"},
            "repos/civitaspo/example/actions/runs/9/artifacts": {"artifacts": [
                {"id": 10, "name": "securefix-merge-request-9", "expired": False, "size_in_bytes": 512}]},
        })
        return run

    def validate_source(self):
        return self.run_step("merge.yml", "Validate the source run",
                             SOURCE_REPOSITORY="civitaspo/example", SOURCE_RUN_ID="9")

    def test_source_requires_successful_original_trusted_workflow(self):
        run = self.source()
        result = self.validate_source()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "outputs").read_text(),
                         "artifact_id=10\nartifact_name=securefix-merge-request-9\nhead_sha=" + "c" * 40 + "\n")
        for changes in [{"conclusion": "failure"}, {"run_attempt": 2}, {"event": "pull_request"},
                        {"head_branch": "attacker"}, {"workflow_id": 4},
                        {"referenced_workflows": []},
                        {"referenced_workflows": [{"path": "untrusted", "sha": "b" * 40}]}]:
            with self.subTest(changes=changes):
                self.source().update(changes)
                self.assertNotEqual(self.validate_source().returncode, 0)

    def test_source_rejects_missing_multiple_or_oversized_artifacts(self):
        self.source()
        endpoint = "repos/civitaspo/example/actions/runs/9/artifacts"
        valid = self.responses[endpoint]["artifacts"][0]
        for artifacts in [[], [valid, valid], [{**valid, "expired": True}],
                          [{**valid, "size_in_bytes": 16385}]]:
            with self.subTest(artifacts=artifacts):
                self.responses[endpoint] = {"artifacts": artifacts}
                self.assertNotEqual(self.validate_source().returncode, 0)

    def test_replay_checks_earlier_workflow_run_pages(self):
        endpoint = "repos/civitaspo/securefix-server/actions/workflows/merge.yml/runs"
        self.responses[endpoint] = {"_pages": [
            {"workflow_runs": [{"id": 12, "display_title": "Merge Pull Request (merge-request-9)"}]},
            {"workflow_runs": [{"id": 13, "display_title": "Unrelated"}]}]}
        result = self.run_step("merge.yml", "Reject a previously handled source request",
                               GITHUB_REPOSITORY="civitaspo/securefix-server",
                               SOURCE_RUN_ID="9", CURRENT_RUN_ID="15")
        self.assertNotEqual(result.returncode, 0)
        self.responses[endpoint] = {"workflow_runs": [{"id": 15, "display_title": "Merge Pull Request (merge-request-9)"}]}
        result = self.run_step("merge.yml", "Reject a previously handled source request",
                               GITHUB_REPOSITORY="civitaspo/securefix-server",
                               SOURCE_RUN_ID="9", CURRENT_RUN_ID="15")
        self.assertEqual(result.returncode, 0, result.stderr)

    def ready(self):
        path, manifest = self.manifest()
        self.responses.update({
            "graphql": {"data": {"repository": {"pullRequest": {"reviewDecision": "APPROVED"}}}},
            "repos/civitaspo/example/commits/" + SHA + "/check-runs": {
                "check_runs": [{"name": "status-check", "status": "completed", "conclusion": "success"}]},
            "repos/civitaspo/example/commits/" + SHA + "/status": {"statuses": []},
            "repos/civitaspo/example/pulls/7/commits": [
                {"commit": {"message": "fix: first\n\nCo-Authored-By: Codex <noreply@openai.com>"}},
                {"commit": {"message": "fix: second\n\nco-authored-by: codex <noreply@openai.com>\nCo-Authored-By: Other <other@example.com>"}}],
            "repos/civitaspo/example/pulls/7/merge": {"merged": True, "sha": "e" * 40},
        })
        self.pr["body"] = "Fix the bug.\n\nCo-Authored-By: Codex <noreply@openai.com>"
        return manifest

    def merge(self, manifest):
        return self.run_step("merge.yml", "Merge the accepted head SHA",
                             SOURCE_REPOSITORY="civitaspo/example", MANIFEST=json.dumps(manifest))

    def test_merge_sends_recorded_sha_squash_and_unique_trailers_without_title(self):
        manifest = self.ready()
        result = self.merge(manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads((self.directory / "payload.json").read_text())
        self.assertEqual(payload, {
            "sha": SHA, "merge_method": "squash",
            "commit_message": "Fix the bug.\n\nCo-Authored-By: Codex <noreply@openai.com>\n\nCo-Authored-By: Other <other@example.com>",
        })
        self.assertEqual((self.directory / "outputs").read_text(), "merge_sha=" + "e" * 40 + "\n")

    def test_wait_does_not_accept_failed_checks_with_approved_review(self):
        manifest = self.ready()
        checks = self.responses["repos/civitaspo/example/commits/" + SHA + "/check-runs"]
        checks["check_runs"][0]["conclusion"] = "failure"
        result = self.run_step("merge.yml", "Wait for required checks and approval",
                               SOURCE_REPOSITORY="civitaspo/example", MANIFEST=json.dumps(manifest))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "outputs").exists())
        self.assertFalse((self.directory / "payload.json").exists())
        interval = int((self.directory / "sleep-call").read_text())
        self.assertGreater(interval, 0)
        self.assertLessEqual(interval, 30)

    def test_wait_accepts_checks_and_review_for_recorded_head(self):
        manifest = self.ready()
        result = self.run_step("merge.yml", "Wait for required checks and approval",
                               SOURCE_REPOSITORY="civitaspo/example", MANIFEST=json.dumps(manifest))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "outputs").read_text(), "head_sha=" + SHA + "\n")

    def test_merge_rejects_changed_sha_comment_draft_and_expiry(self):
        for change in ["head", "comment", "draft", "expired", "sha-conflict"]:
            with self.subTest(change=change):
                manifest = self.ready()
                if change == "head":
                    self.pr["head"]["sha"] = "b" * 40
                elif change == "comment":
                    self.comment["updated_at"] = "2026-02-01T00:00:00Z"
                elif change == "draft":
                    self.pr["draft"] = True
                elif change == "expired":
                    manifest["acceptedAt"] = "2020-01-01T00:00:00Z"
                else:
                    self.responses["repos/civitaspo/example/pulls/7/merge"] = {"_error": "Conflict", "_status": 409}
                self.assertNotEqual(self.merge(manifest).returncode, 0)
                self.pr["head"]["sha"] = SHA
                self.pr["draft"] = False
                self.comment["updated_at"] = "2026-01-01T00:00:00Z"

    def test_notification_records_terminal_result_and_merge_sha(self):
        _, manifest = self.manifest()
        result = self.run_step("merge.yml", "Report the terminal result",
                               SOURCE_REPOSITORY="civitaspo/example", MANIFEST=json.dumps(manifest),
                               MERGE_RESULT="success", MERGE_SHA="e" * 40,
                               SERVER_RUN_ID="15", SERVER_REPOSITORY="civitaspo/securefix-server")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads((self.directory / "payload.json").read_text())
        self.assertEqual(payload["body"], "<!-- securefix-merge-request:9 -->\n"
                         "Securefix merged this pull request with squash at " + "e" * 40 + ".\n\n"
                         "Server run: https://github.com/civitaspo/securefix-server/actions/runs/15")

    def test_cleanup_encodes_label_name_and_tolerates_not_found(self):
        endpoint = "repos/civitaspo/securefix-server/labels/merge-request-%2Fexample"
        self.responses[endpoint] = {"_error": "Not Found", "_status": 404}
        result = self.run_step("merge.yml", "Delete the one-time request label",
                               GITHUB_REPOSITORY="civitaspo/securefix-server", LABEL_NAME="merge-request-/example")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["api", "-X", "DELETE", "/" + endpoint]])


if __name__ == "__main__":
    unittest.main()
