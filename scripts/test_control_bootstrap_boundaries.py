import copy
import io
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from unittest.mock import patch

try:
    import test_control_bootstrap as fixtures
except ModuleNotFoundError:
    from scripts import test_control_bootstrap as fixtures


control = fixtures.control


class BootstrapBoundaryTests(unittest.TestCase):
    def test_immutable_publication_retry_reuses_attested_archive(self):
        expected_policy = b'{"trusted":true}'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("policy.json")
            member.size = len(expected_policy)
            archive.addfile(member, io.BytesIO(expected_policy))
        published = buffer.getvalue()
        digest = control.hashlib.sha256(published).hexdigest()
        release = {
            "immutable": True,
            "draft": False,
            "assets": [{"id": 12, "name": control.ASSET, "size": len(published), "digest": "sha256:" + digest, "state": "uploaded"}],
        }
        with patch.object(control, "request_bytes", return_value=published) as download, patch.object(control, "verify_attestation") as attest:
            self.assertEqual(control.verify_published_immutable_archive("civitaspo/securefix-server", release, "a" * 40, expected_policy), digest)
        download.assert_called_once_with("/repos/civitaspo/securefix-server/releases/assets/12", control.MAX_ARCHIVE)
        attest.assert_called_once()

        bad_release = copy.deepcopy(release)
        bad_release["assets"][0]["digest"] = "sha256:" + "0" * 64
        with patch.object(control, "request_bytes", return_value=published), patch.object(control, "verify_attestation") as attest:
            with self.assertRaisesRegex(RuntimeError, "GitHub metadata"):
                control.verify_published_immutable_archive("civitaspo/securefix-server", bad_release, "a" * 40, expected_policy)
        attest.assert_not_called()

    def test_serialized_merge_gate_requires_exact_server_only_bypass(self):
        policy = {
            "deployment": {
                "server": {"repository": "civitaspo/securefix-server"},
                "server_app_id": 3872533,
                "repository_owner": {"id": 4525500},
            },
            "repositories": [{"repository": "civitaspo/securefix-server", "capabilities": ["merge"]}],
        }
        responses = [
            {"full_name": "civitaspo/securefix-server", "owner": {"id": 4525500}, "allow_auto_merge": False, "allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False},
            [],
            [{"id": 12, "name": "controlled-merges", "source_type": "Repository"}],
            {"id": 12, "source_type": "Repository", "source": "civitaspo/securefix-server", "name": "controlled-merges", "target": "branch", "enforcement": "active", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "bypass_actors": [{"actor_id": 3872533, "actor_type": "Integration", "bypass_mode": "pull_request"}], "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}]},
        ]
        with patch.dict(control.os.environ, {"SECUREFIX_SERVER_APP_READ_TOKEN": "read-only"}), patch.object(control, "request", side_effect=responses) as request:
            control.require_serialized_merge_settings("civitaspo/securefix-server", policy)
        self.assertEqual(request.call_count, 4)
        self.assertTrue(all(call.kwargs.get("token") == "read-only" for call in request.call_args_list))

        responses[3]["rules"] = [{"type": "update"}]
        with patch.dict(control.os.environ, {"SECUREFIX_SERVER_APP_READ_TOKEN": "read-only"}), patch.object(control, "request", side_effect=responses):
            control.require_serialized_merge_settings("civitaspo/securefix-server", policy)
        for rules in (
            [{"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}],
            [{"type": "update", "parameters": {"update_allows_fetch_and_merge": 0}}],
            [{"type": "update", "parameters": None}],
            [{"type": "update", "parameters": {}}],
            [{"type": "update", "unexpected": False}],
        ):
            responses[3]["rules"] = rules
            with self.subTest(rules=rules), patch.dict(control.os.environ, {"SECUREFIX_SERVER_APP_READ_TOKEN": "read-only"}), patch.object(control, "request", side_effect=responses):
                with self.assertRaisesRegex(RuntimeError, "rule set is not exact"):
                    control.require_serialized_merge_settings("civitaspo/securefix-server", policy)
        responses[3]["rules"] = [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}]

        responses[3]["bypass_actors"] = [{"actor_id": 3872533, "actor_type": "Integration", "bypass_mode": "always"}]
        with patch.dict(control.os.environ, {"SECUREFIX_SERVER_APP_READ_TOKEN": "read-only"}), patch.object(control, "request", side_effect=responses):
            with self.assertRaisesRegex(RuntimeError, "pull-request bypass"):
                control.require_serialized_merge_settings("civitaspo/securefix-server", policy)

        responses[3]["bypass_actors"] = [{"actor_id": 3872533, "actor_type": "Integration", "bypass_mode": "pull_request"}]
        responses[3]["conditions"]["ref_name"]["include"] = ["refs/heads/release"]
        with patch.dict(control.os.environ, {"SECUREFIX_SERVER_APP_READ_TOKEN": "read-only"}), patch.object(control, "request", side_effect=responses):
            with self.assertRaisesRegex(RuntimeError, "default branch"):
                control.require_serialized_merge_settings("civitaspo/securefix-server", policy)

    def test_publisher_run_rejects_mismatched_provenance(self):
        good = fixtures.run_fixture(control.BOOTSTRAP_WORKFLOW)
        good.update(status="completed", conclusion="success")
        for field, value in (
            ("path", control.BOOTSTRAP_WORKFLOW + "@refs/heads/untrusted"),
            ("head_branch", "untrusted"),
            ("run_attempt", 2),
            ("head_sha", fixtures.HEAD),
            ("actor", {"id": 1}),
            ("triggering_actor", {"id": 1}),
            ("conclusion", "failure"),
            ("repository", {"full_name": "civitaspo/securefix-server", "id": 1}),
        ):
            with self.subTest(field=field):
                run = copy.deepcopy(good)
                run[field] = value
                with patch.object(control, "request", return_value=run):
                    with self.assertRaises(RuntimeError):
                        control.workflow_run("civitaspo/securefix-server", 77, control.BOOTSTRAP_WORKFLOW, fixtures.MAIN)

    def test_failed_signature_stops_before_status_or_mutation(self):
        with patch.object(control, "request", return_value={"sha": fixtures.MAIN, "commit": {"verification": {"verified": False}}}) as request:
            with self.assertRaisesRegex(RuntimeError, "signature"):
                control.required_status("civitaspo/securefix-server", fixtures.MAIN)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[0], "GET")

    def test_pending_status_context_stops_before_check_lookup(self):
        with patch.object(control, "request", side_effect=[
            {"sha": fixtures.MAIN, "commit": {"verification": {"verified": True}}},
            {"total_count": 1, "state": "pending"},
        ]) as request:
            with self.assertRaisesRegex(RuntimeError, "combined"):
                control.required_status("civitaspo/securefix-server", fixtures.MAIN)
        self.assertEqual(request.call_count, 2)

    def test_latest_owner_review_must_approve_exact_head(self):
        approved = {"user": {"id": control.OWNER_ID}, "state": "APPROVED", "commit_id": fixtures.HEAD, "submitted_at": "2026-10-16T00:00:00Z"}
        for latest in (
            dict(approved, state="CHANGES_REQUESTED", submitted_at="2026-10-16T00:01:00Z"),
            dict(approved, commit_id=fixtures.MAIN, submitted_at="2026-10-16T00:01:00Z"),
        ):
            with self.subTest(latest=latest), patch.object(control, "request", return_value=[approved, latest]):
                with self.assertRaisesRegex(RuntimeError, "latest owner review"):
                    control.validate_review("civitaspo/securefix-server", 1, fixtures.HEAD)
        with patch.object(control, "request", return_value=[approved]):
            control.validate_review("civitaspo/securefix-server", 1, fixtures.HEAD)

    def test_archive_rejects_traversal_links_and_duplicate_policy(self):
        for kind in ("traversal", "link", "duplicate"):
            with self.subTest(kind=kind), tempfile.NamedTemporaryFile() as file:
                with tarfile.open(fileobj=file, mode="w:gz") as archive:
                    policy = tarfile.TarInfo("policy.json")
                    policy.size = 2
                    archive.addfile(policy, io.BytesIO(b"{}"))
                    bad = tarfile.TarInfo("../escape" if kind == "traversal" else "./policy.json" if kind == "duplicate" else "securefix")
                    if kind == "link":
                        bad.type = tarfile.SYMTYPE
                        bad.linkname = "/tmp/other"
                    archive.addfile(bad)
                file.flush()
                with self.assertRaises(RuntimeError):
                    control.archive_policy(file.name)

    def test_archive_returns_exact_policy_and_digest_without_execution(self):
        with tempfile.NamedTemporaryFile() as file:
            with tarfile.open(fileobj=file, mode="w:gz") as archive:
                for name, raw in (("policy.json", b'{"version":1}'), ("securefix", b"not an executable")):
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            file.flush()
            with patch.object(control.subprocess, "run", side_effect=AssertionError("candidate executed")):
                digest, policy = control.archive_policy(file.name)
            file.seek(0)
            self.assertEqual(digest, control.hashlib.sha256(file.read()).hexdigest())
            self.assertEqual(policy, b'{"version":1}')

    def test_scratch_zip_rejects_extra_files(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("state.json", "{}")
            archive.writestr("unreviewed.json", "{}")
        with self.assertRaisesRegex(RuntimeError, "unexpected file set"):
            control.zip_json_files(buffer.getvalue(), ("state.json",))

    def test_binary_redirect_does_not_forward_read_token(self):
        seen = []

        class Opener:
            def open(self, request, timeout):
                seen.append(request)
                if len(seen) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, "Found", {"Location": "https://artifact.example.test/archive.zip"}, None)
                return io.BytesIO(b"bytes")

        with patch.dict(control.os.environ, {"GITHUB_TOKEN": "fixture-read-token"}), patch.object(control.urllib.request, "build_opener", return_value=Opener()):
            self.assertEqual(control.request_bytes("/repos/civitaspo/securefix-server/actions/artifacts/1/zip", 100), b"bytes")
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer fixture-read-token")
        self.assertIsNone(seen[1].get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
