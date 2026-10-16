import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("control-bootstrap.py")
SPEC = importlib.util.spec_from_file_location("control_bootstrap", MODULE_PATH)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


MAIN = "a" * 40
HEAD = "b" * 40


def run_fixture(workflow):
    return {
        "id": 77,
        "repository": {"id": control.SERVER_ID, "full_name": "civitaspo/securefix-server"},
        "head_repository": {"id": control.SERVER_ID, "full_name": "civitaspo/securefix-server"},
        "path": workflow,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": MAIN,
        "run_attempt": 1,
        "actor": {"id": control.OWNER_ID},
        "triggering_actor": {"id": control.OWNER_ID},
        "status": "in_progress",
    }


class BootstrapTests(unittest.TestCase):
    def test_workflow_api_accepts_unsuffixed_path(self):
        with patch.object(control, "request", return_value=run_fixture(control.BOOTSTRAP_WORKFLOW)):
            run = control.workflow_run("civitaspo/securefix-server", 77, control.BOOTSTRAP_WORKFLOW, MAIN, "in_progress")
        self.assertEqual(run["path"], control.BOOTSTRAP_WORKFLOW)

    def test_repair_branch_endpoint_array_is_accepted(self):
        environment = {
            "GITHUB_REPOSITORY": "civitaspo/securefix-server",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": f"civitaspo/securefix-server/{control.BOOTSTRAP_WORKFLOW}@refs/heads/main",
            "GITHUB_ACTOR_ID": str(control.OWNER_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": MAIN,
            "GITHUB_RUN_ID": "77",
        }
        calls = []

        def fixture(method, path, **kwargs):
            calls.append((method, path))
            if path.endswith("commits/main"):
                return {"sha": MAIN}
            if path.endswith("actions/runs/77"):
                return run_fixture(control.BOOTSTRAP_WORKFLOW)
            if "contents/control/active.json?ref=" in path:
                return None
            if f"compare/{MAIN}...{HEAD}" in path:
                return {
                    "base_commit": {"sha": MAIN},
                    "merge_base_commit": {"sha": MAIN},
                    "status": "ahead",
                    "commits": [{"commit": {"verification": {"verified": True}}}],
                    "files": [{"filename": "README.md"}],
                }
            if path.endswith(f"commits/{HEAD}"):
                return {"sha": HEAD, "commit": {"verification": {"verified": True}}}
            if path.endswith(f"commits/{HEAD}/status"):
                return {"state": "success", "total_count": 0}
            if f"commits/{HEAD}/check-runs" in path:
                return {"total_count": 1, "check_runs": [{"name": "status-check", "app": {"id": control.STATUS_APP_ID}, "status": "completed", "conclusion": "success"}]}
            if path.endswith(f"commits/{HEAD}/branches-where-head"):
                return [{"name": "repair/green-head"}]
            if path.startswith("/repos/civitaspo/securefix-server/pulls?"):
                return []
            raise AssertionError(f"unexpected API fixture request: {method} {path}")

        with tempfile.NamedTemporaryFile(mode="w") as event_file:
            json.dump({"inputs": {"phase": "repair-propose"}}, event_file)
            event_file.flush()
            environment["GITHUB_EVENT_PATH"] = event_file.name
            with patch.dict(os.environ, environment, clear=False), patch.object(control, "request", side_effect=fixture), patch.object(control, "current_policy", return_value=({"repositories": []}, b"{}")), patch.object(control, "require_serialized_merge_settings"):
                plan = control.validate_repair_commit(MAIN, HEAD)
        self.assertEqual(plan["branch"], "repair/green-head")
        self.assertIn(("GET", f"/repos/civitaspo/securefix-server/commits/{HEAD}/branches-where-head"), calls)

    def test_control_identity_uses_rust_field_order(self):
        descriptor = {
            "version": 1,
            "generation": 1,
            "source_sha": MAIN,
            "policy_sha256": "1" * 64,
            "archive_sha256": "2" * 64,
            "release_id": 3,
            "asset_id": 4,
            "publisher_run_id": 5,
            "verification_run_id": 6,
            "previous": control.ZERO,
        }
        rust_order = ["version", "generation", "source_sha", "policy_sha256", "archive_sha256", "release_id", "asset_id", "publisher_run_id", "verification_run_id", "previous"]
        expected = control.hashlib.sha256(json.dumps({key: descriptor[key] for key in rust_order}, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(control.canonical_control_id(descriptor), expected)
        reordered = dict(reversed(list(descriptor.items())))
        self.assertEqual(control.canonical_control_id(reordered), expected)

    def test_failed_proposal_retry_refreshes_only_publisher_run_and_invalidates_pr_head(self):
        old_head = "c" * 40
        new_head = "d" * 40
        desired = {
            "version": 1,
            "generation": 1,
            "source_sha": MAIN,
            "policy_sha256": "1" * 64,
            "archive_sha256": "2" * 64,
            "release_id": 3,
            "asset_id": 4,
            "publisher_run_id": 99,
            "verification_run_id": 88,
            "previous": control.ZERO,
        }
        stored = dict(desired, publisher_run_id=77)
        pr = {
            "number": 12,
            "state": "open",
            "user": {"id": control.SERVER_BOT_ID},
            "head": {"ref": "securefix-control-bootstrap-aaaaaaaaaaaa", "sha": old_head, "repo": {"full_name": "civitaspo/securefix-server"}},
            "base": {"ref": "main", "sha": MAIN, "repo": {"full_name": "civitaspo/securefix-server"}},
            "merged_at": None,
        }
        gql = []

        def fixture(method, path, body=None, **kwargs):
            if path.endswith("git/ref/heads/securefix-control-bootstrap-aaaaaaaaaaaa"):
                return {"object": {"sha": old_head}}
            if f"compare/{MAIN}...{old_head}" in path:
                return {
                    "base_commit": {"sha": MAIN},
                    "merge_base_commit": {"sha": MAIN},
                    "status": "ahead",
                    "commits": [{"commit": {"verification": {"verified": True}}}],
                    "files": [{"filename": control.ACTIVE}],
                }
            if f"contents/{control.ACTIVE}?ref={old_head}" in path:
                content = json.dumps(stored).encode()
                return {"type": "file", "path": control.ACTIVE, "encoding": "base64", "size": len(content), "content": control.base64.b64encode(content).decode()}
            if "pulls?state=all" in path:
                return [pr]
            if path.endswith("commits/main"):
                return {"sha": MAIN}
            if f"contents/{control.ACTIVE}?ref={MAIN}" in path:
                return None
            if path == "/graphql":
                gql.append(body)
                return {"data": {"createCommitOnBranch": {"commit": {"oid": new_head}}}}
            if path.endswith("pulls/12"):
                return dict(pr, head=dict(pr["head"], sha=new_head))
            raise AssertionError(f"unexpected API fixture request: {method} {path}")

        with patch.object(control, "request", side_effect=fixture):
            head, resumed_pr, branch_exists = control.resume_descriptor_branch(
                "civitaspo/securefix-server", "securefix-control-bootstrap-aaaaaaaaaaaa", MAIN, desired,
            )
        self.assertTrue(branch_exists)
        self.assertEqual(head, new_head)
        self.assertEqual(resumed_pr["number"], 12)
        input_value = gql[0]["variables"]["input"]
        self.assertEqual(input_value["expectedHeadOid"], old_head)
        updated = json.loads(control.base64.b64decode(input_value["fileChanges"]["additions"][0]["contents"]))
        self.assertEqual(updated, desired)
        self.assertNotEqual(updated["publisher_run_id"], stored["publisher_run_id"])

    def test_absent_descriptor_fails_before_mutation(self):
        environment = {
            "GITHUB_REPOSITORY": "civitaspo/securefix-server",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": f"civitaspo/securefix-server/{control.BOOTSTRAP_WORKFLOW}@refs/heads/main",
            "GITHUB_ACTOR_ID": str(control.OWNER_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": MAIN,
            "GITHUB_RUN_ID": "77",
        }
        calls = []

        def fixture(method, path, **kwargs):
            calls.append(method)
            if path.endswith("commits/main"):
                return {"sha": MAIN}
            if path.endswith("actions/runs/77"):
                return run_fixture(control.BOOTSTRAP_WORKFLOW)
            if "contents/control/active.json?ref=" in path:
                return {"type": "file", "path": control.ACTIVE}
            raise AssertionError(f"unexpected API fixture request: {method} {path}")

        plan = {"repository": "civitaspo/securefix-server", "operation": "prepare", "source_sha": MAIN, "verification_run_id": 78}
        with tempfile.NamedTemporaryFile() as archive, patch.dict(os.environ, environment, clear=False), patch.object(control, "request", side_effect=fixture):
            with self.assertRaisesRegex(RuntimeError, "permanently disabled"):
                control.create_descriptor_pr(plan, archive.name)
        self.assertTrue(calls)
        self.assertTrue(all(method == "GET" for method in calls))

    def test_bootstrap_writer_workflow_never_executes_candidate_binary(self):
        workflow = (MODULE_PATH.parent.parent / ".github/workflows/control-bootstrap.yml").read_text()
        self.assertNotIn("distribution/securefix ", workflow)
        self.assertNotIn("bootstrap-runtime/securefix", workflow)
        self.assertIn("Revalidate bootstrap PR without candidate execution", workflow)


if __name__ == "__main__":
    unittest.main()
