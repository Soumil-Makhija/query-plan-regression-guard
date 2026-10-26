"""Strict manifests and selection against real committed Git histories."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from plan_guard.manifest import load_manifest, select_queries


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "queries").mkdir()
        (self.root / "queries/orders.sql").write_text("SELECT * FROM orders WHERE id = %s\n")
        (self.root / "queries/users.sql").write_text("SELECT * FROM users\n")
        self.path = self.root / "guard.json"
        self.data = {"schema_version": 1, "queries": [
            {"id": "orders", "sql": "queries/orders.sql", "params": [42], "sources": ["app/**/*.py"]},
            {"id": "users", "sql": "queries/users.sql", "params": {"active": True}}],
            "migrations": ["migrations/**"], "policy": {"cost_ratio": 3}}
        self.write()

    def write(self, data=None):
        self.path.write_text(json.dumps(self.data if data is None else data))

    def test_loads_real_sql_and_defaults_with_absolute_paths(self):
        manifest = load_manifest(str(self.path))
        self.assertEqual(self.root.resolve(), manifest["root"])
        self.assertEqual(self.path.resolve(), manifest["path"])
        self.assertEqual("queries/orders.sql", manifest["queries"]["orders"]["sql_path"])
        self.assertIn("WHERE id = %s", manifest["queries"]["orders"]["sql"])
        self.assertEqual([42], manifest["queries"]["orders"]["params"])
        self.assertEqual([], manifest["queries"]["users"]["sources"])
        self.assertEqual({"cost_ratio": 3}, manifest["policy"])
        selected, metadata = select_queries(manifest)
        self.assertEqual(["orders", "users"], selected)
        self.assertEqual("all", metadata["mode"])

    def test_unknown_fields_duplicate_ids_and_invalid_shapes_fail(self):
        mutations = [lambda d: d.update(extra=1), lambda d: d.update(schema_version=True),
                     lambda d: d.update(queries=[]), lambda d: d.update(queries={}),
                     lambda d: d["queries"][0].update(extra=1),
                     lambda d: d["queries"][1].update(id="orders"),
                     lambda d: d["queries"][0].update(id=" "),
                     lambda d: d["queries"][0].update(params=42),
                     lambda d: d["queries"][0].update(sources="app/*"),
                     lambda d: d.update(migrations="migrations/*"),
                     lambda d: d.update(policy={"unknown": 1}),
                     lambda d: d.update(policy={"cost_ratio": True}),
                     lambda d: d.update(policy={"cost_ratio": 1}),
                     lambda d: d.update(policy={"max_selectivity": 1.5})]
        for mutation in mutations:
            data = copy.deepcopy(self.data)
            mutation(data)
            self.write(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                load_manifest(self.path)

    def test_duplicate_json_fields_and_nonfinite_values_fail(self):
        for text in ('{"schema_version":1,"schema_version":1,"queries":[]}',
                     json.dumps(self.data).replace('[42]', '[NaN]'),
                     json.dumps(self.data).replace('[42]', '[Infinity]'),
                     json.dumps(self.data).replace('[42]', '[1e999]')):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_manifest(self.path)

    def test_paths_and_globs_cannot_escape(self):
        for value in ("../outside.sql", "/outside.sql", "queries/../../outside.sql", "C:/outside.sql", "queries\\x.sql"):
            for field in ("sql", "sources", "migrations"):
                data = copy.deepcopy(self.data)
                if field == "migrations":
                    data[field] = [value]
                else:
                    data["queries"][0][field] = value if field == "sql" else [value]
                self.write(data)
                with self.subTest(value=value, field=field), self.assertRaises(ValueError):
                    load_manifest(self.path)

    def test_missing_non_utf8_empty_or_symlink_escaping_sql_fails(self):
        sql = self.root / "queries/orders.sql"
        for content in (b"", b" \n", b"\xff"):
            sql.write_bytes(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                load_manifest(self.path)
        sql.unlink()
        with self.assertRaises(ValueError):
            load_manifest(self.path)
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.sql"
            target.write_text("SELECT 1")
            sql.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "escapes"):
                load_manifest(self.path)


class GitSelectionTests(ManifestTests):
    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        self.git("config", "user.name", "Selection Test")
        self.git("config", "user.email", "test@example.invalid")
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True, text=True).stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)

    def change(self, path, text="changed"):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
        self.commit("change " + path.replace("\n", "newline"))

    def selection(self):
        return select_queries(load_manifest(self.path), self.base)

    def test_sql_changed_selects_only_its_query_and_records_resolved_commits(self):
        self.change("queries/orders.sql", "SELECT * FROM orders WHERE id = %s AND active")
        selected, metadata = self.selection()
        self.assertEqual(["orders"], selected)
        self.assertEqual(["queries/orders.sql"], metadata["changed_paths"])
        self.assertEqual(self.base, metadata["base"])
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), metadata["head"])
        self.assertEqual("committed_HEAD", metadata["scope"])

    def test_source_glob_matches_zero_and_multiple_directories(self):
        self.change("app/orders.py")
        self.assertEqual(["orders"], self.selection()[0])
        self.base = self.git("rev-parse", "HEAD").strip()
        self.change("app/nested/more/orders.py")
        self.assertEqual(["orders"], self.selection()[0])

    def test_internal_sql_symlink_target_is_an_implicit_dependency(self):
        (self.root / "queries/actual.sql").write_text("SELECT 1")
        (self.root / "queries/orders.sql").unlink()
        (self.root / "queries/orders.sql").symlink_to("actual.sql")
        self.commit("internal SQL symlink")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.change("queries/actual.sql", "SELECT 2")
        manifest = load_manifest(self.path)
        self.assertEqual("queries/actual.sql", manifest["queries"]["orders"]["resolved_sql_path"])
        self.assertEqual(["orders"], select_queries(manifest, self.base)[0])

    def test_retargeted_directory_symlink_selects_dependent_query(self):
        for directory in ("sql_a", "sql_b"):
            (self.root / directory).mkdir()
            (self.root / directory / "orders.sql").write_text("SELECT 1")
        link = self.root / "sql_link"
        link.symlink_to("sql_a", target_is_directory=True)
        self.data["queries"][0]["sql"] = "sql_link/orders.sql"
        self.write()
        self.commit("directory SQL symlink")
        self.base = self.git("rev-parse", "HEAD").strip()
        link.unlink()
        link.symlink_to("sql_b", target_is_directory=True)
        self.commit("retarget SQL directory")
        manifest = load_manifest(self.path)
        self.assertIn("sql_link", manifest["queries"]["orders"]["sql_dependencies"])
        selected, metadata = select_queries(manifest, self.base)
        self.assertEqual(["orders"], selected)
        self.assertEqual(["sql_link"], metadata["changed_paths"])

    def test_migration_or_manifest_changed_selects_every_query(self):
        self.change("migrations/001_drop_index.sql", "DROP INDEX orders_idx")
        self.assertEqual(["orders", "users"], self.selection()[0])
        self.base = self.git("rev-parse", "HEAD").strip()
        self.data["policy"]["cost_ratio"] = 4
        self.write()
        self.commit("policy change")
        self.assertEqual(["orders", "users"], self.selection()[0])
        self.assertIn("Manifest changed", self.selection()[1]["reason"])

    def test_unrelated_and_uncommitted_changes_are_excluded(self):
        self.change("README.md")
        (self.root / "queries/orders.sql").write_text("SELECT 2")
        (self.root / "app").mkdir()
        (self.root / "app/untracked.py").write_text("new")
        self.assertEqual([], self.selection()[0])
        self.assertEqual(["README.md"], self.selection()[1]["changed_paths"])

    def test_merge_base_excludes_changes_only_on_target_branch(self):
        self.git("branch", "feature")
        self.change("app/target_only.py")
        target = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "feature")
        self.change("README.md")
        selected, metadata = select_queries(load_manifest(self.path), target)
        self.assertEqual([], selected)
        self.assertEqual(["README.md"], metadata["changed_paths"])

    def test_nul_delimited_diff_preserves_newline_and_space_paths(self):
        self.change("app/new\nline name.py")
        selected, metadata = self.selection()
        self.assertEqual(["orders"], selected)
        self.assertEqual(["app/new\nline name.py"], metadata["changed_paths"])

    def test_rename_is_delete_plus_add(self):
        self.change("app/old.py")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("mv", "app/old.py", "app/new.py")
        self.commit("rename source")
        selected, metadata = self.selection()
        self.assertEqual(["orders"], selected)
        self.assertEqual(["app/new.py", "app/old.py"], metadata["changed_paths"])

    def test_missing_or_option_like_base_fails_closed(self):
        for base in ("does-not-exist", "--help", "", "\x00", "HEAD~100"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                select_queries(load_manifest(self.path), base)

    def test_manifest_subdirectory_maps_paths_without_selecting_other_app(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "query.sql").write_text("SELECT 1")
        manifest_path = nested / "guard.json"
        manifest_path.write_text(json.dumps({"schema_version": 1, "queries": [
            {"id": "nested", "sql": "query.sql", "sources": ["app/**"]}]}))
        self.commit("nested manifest")
        base = self.git("rev-parse", "HEAD").strip()
        self.change("app/outside.py")
        self.assertEqual([], select_queries(load_manifest(manifest_path), base)[0])
        self.change("nested/app/inside.py")
        selected, metadata = select_queries(load_manifest(manifest_path), base)
        self.assertEqual(["nested"], selected)
        self.assertEqual("nested", metadata["root_prefix"])


if __name__ == "__main__":
    unittest.main()
