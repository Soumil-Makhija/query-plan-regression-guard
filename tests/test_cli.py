"""CLI artifact, failure-policy, selection, and secret-handling behavior."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from plan_guard import cli
from plan_guard.report import to_markdown
from tests.test_analysis import scan, snapshot, trace


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def run_cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = cli.main(argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_compare_writes_deterministic_json_markdown_and_obeys_failure_thresholds(self):
        baseline = self.write("baseline.json", snapshot(scan("Index Scan", cost=40)))
        candidate = self.write("candidate.json", snapshot(scan(cost=200)))
        output = self.root / "nested" / "report.json"
        markdown = self.root / "report.md"
        args = ["compare", "--baseline", baseline, "--candidate", candidate,
                "--output", str(output), "--markdown", str(markdown)]
        result, _, error = self.run_cli(args)
        self.assertEqual((1, ""), (result, error))
        report = json.loads(output.read_text())
        self.assertEqual(2, report["summary"]["errors"])
        self.assertIn("INDEX\\_TO\\_SEQ\\_SCAN", markdown.read_text())
        self.assertEqual(0, self.run_cli(args + ["--fail-on", "none"])[0])
        static = self.write("static.json", snapshot())
        args[args.index(candidate)] = static
        args[args.index(baseline)] = static
        self.assertEqual(0, self.run_cli(args + ["--fail-on", "error"])[0])
        self.assertEqual(1, self.run_cli(args)[0])

    def test_compare_marks_new_query_as_incomplete_coverage(self):
        baseline = snapshot()
        baseline["queries"] = {}
        old_path = self.write("old.json", baseline)
        new_path = self.write("new.json", snapshot(scan("Index Scan")))
        output = self.root / "report.json"
        result, _, _ = self.run_cli(["compare", "--baseline", old_path, "--candidate", new_path, "--output", str(output)])
        self.assertEqual(1, result)
        report = json.loads(output.read_text())
        self.assertEqual(["NEW_QUERY", "BASELINE_MISSING"], [f["code"] for f in report["findings"]])
        self.assertEqual(1, report["summary"]["warnings"])

    def test_trace_subprocess_exit_codes_and_offline_import(self):
        project = str(Path(__file__).resolve().parents[1])
        input_path = self.write("trace.json", trace())
        output = self.root / "trace-report.json"
        command = [sys.executable, "-m", "plan_guard.cli", "trace", "--input", input_path, "--output", str(output)]
        result = subprocess.run(command, cwd=project, text=True, capture_output=True, check=False)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("POTENTIAL_N_PLUS_ONE", json.loads(output.read_text())["findings"][0]["code"])
        clean_path = self.write("clean.json", trace(params="same"))
        command[command.index(input_path)] = clean_path
        self.assertEqual(0, subprocess.run(command, cwd=project, capture_output=True, check=False).returncode)
        command[command.index(clean_path)] = str(self.root / "missing.json")
        self.assertEqual(2, subprocess.run(command, cwd=project, capture_output=True, check=False).returncode)
        # Importing the command does not import the database driver/module.
        probe = subprocess.run([sys.executable, "-c", "import sys; import plan_guard.cli; assert 'plan_guard.db' not in sys.modules; assert 'psycopg' not in sys.modules"],
                               cwd=project, text=True, capture_output=True, check=False)
        self.assertEqual(0, probe.returncode, probe.stderr)

    def test_capture_forwards_selection_timeout_and_writes_snapshot(self):
        selected = {"mode": "changed", "selected_query_ids": ["orders"]}
        manifest = {"policy": {}, "queries": {}}
        output = self.root / "capture.json"
        with patch.object(cli, "load_manifest", return_value=manifest), \
             patch.object(cli, "select_queries", return_value=(["orders"], selected)), \
             patch.object(cli, "capture_snapshot", return_value=snapshot(scan("Index Scan"))) as capture, \
             patch.dict(os.environ, {"TEST_GUARD_DSN": "postgresql://secret:password@host/db"}):
            result, _, error = self.run_cli(["capture", "--manifest", "manifest.json", "--output", str(output),
                                            "--base", "HEAD~1", "--dsn-env", "TEST_GUARD_DSN",
                                            "--statement-timeout-ms", "900", "--lock-timeout-ms", "100"])
        self.assertEqual((0, ""), (result, error))
        capture.assert_called_once_with(manifest, ["orders"], "postgresql://secret:password@host/db",
                                        statement_timeout_ms=900, lock_timeout_ms=100)
        self.assertEqual(selected, json.loads(output.read_text())["selection"])

    def test_check_filters_unselected_baseline_and_warns_for_selected_missing_baseline(self):
        baseline = snapshot(scan("Index Scan", cost=200))
        baseline["queries"]["unselected"] = copy.deepcopy(baseline["queries"]["orders"])
        path = self.write("baseline.json", baseline)
        output = self.root / "report.json"
        args = ["check", "--manifest", "manifest.json", "--baseline", path, "--output", str(output)]
        with patch.object(cli, "load_manifest", return_value={"policy": {}}), \
             patch.object(cli, "select_queries", return_value=(["orders"], {"mode": "changed"})), \
             patch.object(cli, "capture_snapshot", return_value=snapshot(scan("Index Scan", cost=200))), \
             patch.dict(os.environ, {"PLAN_GUARD_DSN": "test"}):
            self.assertEqual(0, self.run_cli(args)[0])
            report = json.loads(output.read_text())
            self.assertEqual([], report["removed_query_ids"])
            self.assertEqual(["orders"], report["compared_query_ids"])
            baseline["queries"].pop("orders")
            self.write("baseline.json", baseline)
            self.assertEqual(1, self.run_cli(args)[0])
            report = json.loads(output.read_text())
            self.assertIn("BASELINE_MISSING", [f["code"] for f in report["findings"]])

    def test_empty_check_skips_connection_and_reports_explicit_empty_scope(self):
        baseline = self.write("baseline.json", snapshot())
        output = self.root / "report.json"
        with patch.object(cli, "load_manifest", return_value={"policy": {}}), \
             patch.object(cli, "select_queries", return_value=([], {"mode": "changed"})), \
             patch.object(cli, "capture_snapshot") as capture, \
             patch.dict(os.environ, {}, clear=True):
            args = ["check", "--manifest", "manifest.json", "--baseline", baseline, "--output", str(output)]
            self.assertEqual(0, self.run_cli(args)[0])
            report = json.loads(output.read_text())
            self.assertEqual([], report["analyzed_query_ids"])
            self.assertEqual("NO_QUERIES_SELECTED", report["findings"][0]["code"])
            self.assertEqual(2, self.run_cli(["capture", "--manifest", "manifest.json", "--output", str(output)])[0])
            capture.assert_not_called()

    def test_database_errors_are_generic_and_do_not_write_or_leak_secrets(self):
        output = self.root / "report.json"
        secret = "postgresql://user:TOP_SECRET@host/db SQL parameter ALSO_SECRET"
        with patch.object(cli, "load_manifest", return_value={"policy": {}}), \
             patch.object(cli, "select_queries", return_value=(["orders"], {})), \
             patch("plan_guard.db.capture", side_effect=ValueError(secret)), \
             patch.dict(os.environ, {"PLAN_GUARD_DSN": secret}):
            result, stdout, stderr = self.run_cli(["capture", "--manifest", "manifest.json", "--output", str(output)])
        self.assertEqual(2, result)
        self.assertIn("database capture failed (ValueError)", stderr)
        self.assertNotIn("TOP_SECRET", stdout + stderr)
        self.assertNotIn("ALSO_SECRET", stdout + stderr)
        self.assertFalse(output.exists())

    def test_atomic_failure_preserves_existing_file_and_removes_temporary_file(self):
        output = self.root / "existing.json"
        output.write_text("original", encoding="utf-8")
        with patch.object(cli.os, "replace", side_effect=OSError("denied")):
            with self.assertRaises(OSError):
                cli._atomic_write(str(output), "replacement")
        self.assertEqual("original", output.read_text())
        self.assertEqual([output], list(self.root.iterdir()))

    def test_markdown_escapes_untrusted_text_and_cannot_close_evidence_fence(self):
        report = {"summary": {"errors": 0, "warnings": 1, "infos": 0}, "findings": [
            {"severity": "warning", "code": "<img src=x onerror=alert(1)>", "query_id": "[click](https://bad.invalid)",
             "message": "table | break\n# Heading", "evidence": {"value": "```\n<script>alert(1)</script>\n```"}}]}
        markdown = to_markdown(report)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("[click](https://bad.invalid)", markdown)
        self.assertIn("table \\| break<br>\\# Heading", markdown)
        self.assertIn("````json", markdown)
        self.assertEqual(2, markdown.count("````"))

    def test_invalid_policy_and_output_collision_do_not_overwrite_artifacts(self):
        data = self.write("snapshot.json", snapshot())
        bad_policy = self.write("policy.json", {"cost_ratio": 0})
        output = self.root / "report.json"
        args = ["compare", "--baseline", data, "--candidate", data, "--output", str(output)]
        self.assertEqual(2, self.run_cli(args + ["--policy", bad_policy])[0])
        self.assertFalse(output.exists())
        self.assertEqual(2, self.run_cli(args + ["--markdown", str(output)])[0])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
