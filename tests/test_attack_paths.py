import unittest

from core.attack_paths import build_attack_path_graph


class AttackPathGraphTests(unittest.TestCase):
    def test_only_direct_evidence_links_are_graph_edges(self):
        findings = [
            {"id": "F1", "title": "Observed web header gap", "severity": "Low", "confidence": "Observed",
             "asset": "https://example.test/", "evidence_id": "E1"},
            {"id": "F2", "title": "Observed service", "severity": "Medium", "confidence": "Medium",
             "asset": "192.0.2.10", "evidence_id": "E2"},
            {"id": "F3", "title": "Unlinked record", "severity": "High", "confidence": "Low",
             "asset": "192.0.2.10", "evidence_id": "MISSING"},
        ]
        evidence = [{"id": "E1", "type": "web", "source": "HTTP", "data_class": "black_box"},
                    {"id": "E2", "type": "nmap", "source": "Nmap", "data_class": "live"}]

        graph = build_attack_path_graph(findings, evidence)

        self.assertEqual(graph["edges"], [
            {"from": "E1", "to": "F1", "relation": "supports", "evidence_id": "E1"},
            {"from": "E2", "to": "F2", "relation": "supports", "evidence_id": "E2"},
        ])
        self.assertEqual(graph["correlation_candidates"], [])
        self.assertEqual(graph["paths"], [])

    def test_same_explicit_asset_yields_theoretical_candidate_without_ordered_path_claim(self):
        findings = [
            {"id": "F2", "title": "Second observation", "severity": "Medium", "confidence": "Observed",
             "asset": "example.test", "evidence_id": "E2"},
            {"id": "F1", "title": "First observation", "severity": "Low", "confidence": "Observed",
             "asset": " example.test ", "evidence_id": "E1"},
        ]
        evidence = [{"id": "E1", "data_class": "black_box"}, {"id": "E2", "data_class": "live"}]

        graph = build_attack_path_graph(findings, evidence)

        candidate = graph["correlation_candidates"][0]
        self.assertEqual(candidate["finding_ids"], ["F1", "F2"])
        self.assertEqual(candidate["classification"], "theoretical")
        self.assertFalse(candidate["ordered_exploit_chain_verified"])
        self.assertEqual(graph["paths"], [])

    def test_duplicate_findings_and_empty_assets_do_not_create_candidates(self):
        findings = [{"id": "F1", "asset": "", "evidence_id": "E1"},
                    {"id": "F1", "asset": "", "evidence_id": "E1"}]
        graph = build_attack_path_graph(findings, [{"id": "E1"}])
        self.assertEqual(graph["correlation_candidates"], [])
        self.assertEqual(len(graph["nodes"]), 2)

    def test_bridge_builds_graph_from_persisted_assessment_records(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "graph.db")
            original = app.store
            try:
                app.store = test_store
                assessment = test_store.create_assessment({"name": "Evidence graph"})
                aid = assessment["id"]
                execution = test_store.start_execution(aid, "review", "test", "test")
                evidence_id = test_store.add_evidence(aid, execution, "test", "unit", {"observed": True})
                test_store.add_finding(aid, execution, "Observed fact", "Low", "description", "impact",
                    "test", "rule", "recommendation", evidence_id, asset="host.example")

                graph = app.Bridge().attack_path_analysis(aid)

                self.assertEqual(len(graph["edges"]), 1)
                self.assertEqual(graph["edges"][0]["evidence_id"], evidence_id)
                self.assertEqual(len(graph["paths"]), 0)
            finally:
                test_store.close()
                app.store = original


if __name__ == "__main__":
    unittest.main()
