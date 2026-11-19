import json
from tempfile import TemporaryDirectory
import unittest
from datetime import date
from pathlib import Path
from hunter import approved_workflows, choose_repos, workflow_findings, safe_repo_name, safe_filename

class TestHunter(unittest.TestCase):
    def test_name_validation(self):
        self.assertTrue(safe_repo_name("my_repo"))
        self.assertFalse(safe_repo_name("../../../api"))
        self.assertTrue(safe_filename("test.yaml"))
        self.assertFalse(safe_filename("../../test.yaml"))
    def test_selection(self):
        r = ["a", "b", "c", "d"]
        selected = choose_repos(r, 2, date(2026, 11, 17))
        self.assertEqual(len(selected), 2)
        self.assertEqual(len(set(selected)), 2)
    def test_workflow_flag(self):
        content = (Path(__file__).resolve().parent.parent / "examples" / "suspicious-workflow.yml").read_text()
        flags = workflow_findings("demo", "example.yaml", content, "main")
        rules = {f["rule"] for f in flags}
        self.assertIn("PRT_HEAD_EXECUTION_CANDIDATE", rules)
        self.assertIn("UNTRUSTED_EXPRESSION_IN_SHELL", rules)
        self.assertTrue(all(not f["validated"] for f in flags))
    def test_read_only_not_flagged(self):
        content = "on: push\njobs:\n  safe:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo test\n"
        self.assertFalse(workflow_findings("demo", "safe.yml", content, "main"))

    def test_scope_allows_only_explicit_approved_workflow_paths(self):
        with TemporaryDirectory() as folder:
            checkout = Path(folder).resolve()
            name = ".github/workflows/ci.yml"
            workflow = checkout / name
            workflow.parent.mkdir(parents=True)
            workflow.touch()
            scope_file = checkout / "scope.json"
            scope = {
                "activity": "offline-workflow-review",
                "approved": True,
                "rules_reference": "Owner approval",
                "checkout": str(checkout),
                "files": [name],
            }
            scope_file.write_text(json.dumps(scope))
            self.assertEqual(approved_workflows(checkout, scope_file), {workflow: name})
            for change in (
                {"approved": False},
                {"approved": "true"},
                {"activity": "network-review"},
                {"rules_reference": ""},
                {"checkout": str(checkout.parent)},
                {"files": []},
                {"files": [name, ".github/workflows/*"]},
                {"files": [".github/workflows/../ci.yml"]},
                {"files": [name, name]},
            ):
                with self.subTest(change=change):
                    scope_file.write_text(json.dumps(scope | change))
                    with self.assertRaises(ValueError):
                        approved_workflows(checkout, scope_file)

if __name__ == "__main__":
    unittest.main()
