import unittest

from core.source_analysis import analyze_files, analyze_repository


class SourceAnalysisTests(unittest.TestCase):
    def test_repository_analysis_excludes_generated_secret_files_and_indexes_dependencies(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "handler.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.31.0\n# ignored comment\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({"dependencies": {"safe-lib": "^1.2.0"}}), encoding="utf-8")
            (root / ".env").write_text("API_KEY=must-never-appear-987654321\n", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dependency.js").write_text("eval(x)", encoding="utf-8")

            result = analyze_repository(root)

        self.assertEqual(result["execution"], "read_only_no_code_execution")
        self.assertEqual(result["files_analyzed"], 3)
        self.assertEqual({item["name"] for item in result["dependencies"]}, {"requests", "safe-lib"})
        self.assertNotIn("must-never-appear-987654321", str(result))
        self.assertNotIn("node_modules/dependency.js", str(result))
        self.assertIn("SOURCE-REPOSITORY-EVIDENCE", result["scanner"])
        self.assertTrue(any(item["rule_id"] == "PY-DYNAMIC-EVAL" for item in result["indicators"]))

    def test_repository_analysis_rejects_symlink_root(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            real = Path(temp_dir) / "real"
            real.mkdir()
            link = Path(temp_dir) / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                analyze_repository(link)

    def test_reports_redacted_secret_indicators_without_returning_literal(self):
        result = analyze_files([{"path": "settings.py", "content": "api_key = 'sensitive-placeholder-12345'\n"}])
        self.assertEqual(len(result["indicators"]), 1)
        indicator = result["indicators"][0]
        self.assertEqual(indicator["rule_id"], "SOURCE-SECRET-LITERAL")
        self.assertEqual(indicator["line"], 1)
        self.assertNotIn("sensitive-placeholder-12345", str(result))
        self.assertIn("withheld", indicator["excerpt"].lower())

    def test_dynamic_execution_is_a_review_indicator_not_claimed_as_exploitable(self):
        result = analyze_files([{"path": "handler.py", "content": "eval(user_input)\n"}])
        self.assertEqual(result["indicators"][0]["rule_id"], "PY-DYNAMIC-EVAL")
        self.assertIn("review", result["indicators"][0]["title"].lower())
        self.assertEqual(result["indicators"][0]["confidence"], "Observed")

    def test_skips_oversized_and_unsupported_inputs_with_reason(self):
        result = analyze_files([
            {"path": "bundle.bin", "content": "x"},
            {"path": "large.py", "content": "x" * (2 * 1024 * 1024 + 1)},
        ])
        self.assertEqual(result["files_analyzed"], 0)
        self.assertEqual(len(result["skipped"]), 2)

    def test_empty_and_clean_source_returns_no_findings(self):
        result = analyze_files([{"path": "app.py", "content": "def hello():\n    return 'world'\n"}])
        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["files_analyzed"], 1)


if __name__ == "__main__":
    unittest.main()

class SourceReviewBridgeTests(unittest.TestCase):
    def test_bridge_persists_redacted_findings_and_evidence(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "config.py"
            source.write_text("api_key = 'review-only-secret-value'\n", encoding="utf-8")
            test_store = Store(Path(temp_dir) / "review.db")
            original = app.store
            try:
                app.store = test_store
                bridge = app.Bridge()
                bridge._source_selections["test-token"] = [source]
                with self.assertRaises(ValueError):
                    bridge.analyze_source_selection("test-token", authorized=False)
                bridge._source_selections["test-token"] = [source]
                response = bridge.analyze_source_selection("test-token", authorized=True)
                state = test_store.state(response["assessment_id"])
                self.assertEqual(len(state["evidence"]), 1)
                self.assertEqual(len(state["findings"]), 1)
                self.assertNotIn("review-only-secret-value", str(state["evidence"]))
                self.assertNotIn("review-only-secret-value", str(state["findings"]))
                self.assertEqual(response["result"]["execution"], "read_only_no_code_execution")
            finally:
                test_store.close()
                app.store = original

    def test_repository_bridge_requires_authorization_and_persists_redacted_evidence(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            root.mkdir()
            (root / "app.py").write_text("api_key = 'repository-secret-value-1234'\n", encoding="utf-8")
            test_store = Store(Path(temp_dir) / "repository.db")
            original = app.store
            try:
                app.store = test_store
                bridge = app.Bridge()
                bridge._source_repository_selections["repo-token"] = root
                with self.assertRaises(ValueError):
                    bridge.analyze_source_repository("repo-token", authorized=False)
                bridge._source_repository_selections["repo-token"] = root
                response = bridge.analyze_source_repository("repo-token", authorized=True)
                state = test_store.state(response["assessment_id"])
                self.assertEqual(response["result"]["files_analyzed"], 1)
                self.assertEqual(state["evidence"][0]["test_id"], "repository_analysis")
                self.assertEqual(len(state["findings"]), 1)
                self.assertNotIn("repository-secret-value-1234", str(state["evidence"]))
                self.assertNotIn(str(root), str(state["evidence"]))
            finally:
                test_store.close()
                app.store = original
