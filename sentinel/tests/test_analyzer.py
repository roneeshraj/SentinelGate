"""
Unit tests for Gap Analyzer, Blast Radius Modeler, and Proof-of-Excess Demonstrator.
"""

import unittest
from sentinel.database import init_db
from sentinel.analyzer.gap_analyzer import GapAnalyzer
from sentinel.analyzer.blast_radius import BlastRadiusModeler
from sentinel.analyzer.demonstrator import PermissionDemonstrator
from sentinel.models import RiskLevel

class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        init_db(force_reseed=True)

    def test_finch_slack_bot_audit(self):
        # Slack bot was granted 6 scopes, but only uses directory:read and company:read
        audit = GapAnalyzer.audit_credential("cred_finch_slack_001")
        self.assertIsNotNone(audit)
        self.assertEqual(audit.client_name, "Slack Org & Birthday Bot")
        self.assertIn("ssn:read", audit.unused_scopes)
        self.assertIn("pay_statement:read", audit.unused_scopes)
        self.assertGreater(audit.excess_ratio, 60.0) # 4 out of 6 unused = 66.7%
        self.assertIn(audit.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertTrue(len(audit.threat_vectors) > 0)

    def test_harbor_argo_cd_audit(self):
        # ArgoCD was granted system:admin, but only uses repository:pull
        audit = GapAnalyzer.audit_credential("cred_harbor_argo_001")
        self.assertIsNotNone(audit)
        self.assertIn("system:admin", audit.unused_scopes)
        self.assertIn("webhook:manage", audit.unused_scopes)
        self.assertEqual(audit.risk_level, RiskLevel.CRITICAL)

    def test_blast_radius_graph(self):
        audit = GapAnalyzer.audit_credential("cred_finch_slack_001")
        nodes, edges = BlastRadiusModeler.generate_graph(audit)
        self.assertGreater(len(nodes), 3)
        self.assertGreater(len(edges), 3)
        
        # Verify node types
        types = [n["type"] for n in nodes]
        self.assertIn("TOKEN", types)
        self.assertIn("EXCESS_SCOPE", types)
        self.assertIn("EXPOSED_ASSET", types)

    def test_demonstration_proof(self):
        demo = PermissionDemonstrator.demonstrate_token_risk("cred_finch_slack_001")
        self.assertIn("legitimate_request", demo)
        self.assertIn("excessive_demonstration", demo)
        self.assertEqual(demo["legitimate_request"]["status_code"], 200)
        # Because the token currently has excessive scopes, the unauthorized request succeeds!
        self.assertTrue(demo["excessive_demonstration"]["exploit_allowed"])

if __name__ == "__main__":
    unittest.main()
