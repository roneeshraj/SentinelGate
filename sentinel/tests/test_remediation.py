"""
Unit tests for Policy Synthesizer, Remediation execution, and Rollback.
"""

import unittest
from sentinel.database import init_db, get_credential_by_id
from sentinel.remediation.policy_generator import PolicyGenerator
from sentinel.remediation.remediator import Remediator

class TestRemediation(unittest.TestCase):

    def setUp(self):
        init_db(force_reseed=True)

    def test_generate_and_apply_remediation_plan(self):
        cred_id = "cred_finch_slack_001"
        plan = PolicyGenerator.generate_plan(cred_id)
        
        self.assertIsNotNone(plan)
        self.assertEqual(plan.credential_id, cred_id)
        # Slack bot only observed directory:read and company:read
        self.assertIn("directory:read", plan.recommended_scopes)
        self.assertIn("company:read", plan.recommended_scopes)
        self.assertNotIn("ssn:read", plan.recommended_scopes)
        self.assertIn("ssn:read", plan.revoked_scopes)
        self.assertGreater(plan.reduction_percentage, 50.0)

        # Apply plan
        res = Remediator.apply_plan(plan.id)
        self.assertTrue(res["success"])

        # Check credential in DB has been down-scoped
        updated_cred = get_credential_by_id(cred_id)
        self.assertEqual(updated_cred["status"], "REMEDIATED")
        self.assertNotIn("ssn:read", updated_cred["granted_scopes"])
        self.assertIn("directory:read", updated_cred["granted_scopes"])

        # Test Rollback
        rollback_res = Remediator.rollback_plan(plan.id)
        self.assertTrue(rollback_res["success"])
        reverted_cred = get_credential_by_id(cred_id)
        self.assertIn("ssn:read", reverted_cred["granted_scopes"])
        self.assertEqual(reverted_cred["status"], "ACTIVE")

if __name__ == "__main__":
    unittest.main()
