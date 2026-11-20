"""
Unit tests for Sentinel Proxy Gateway enforcement and telemetry interception.
"""

import unittest
from sentinel.database import init_db, set_proxy_mode, get_proxy_mode
from sentinel.config import MODE_MONITOR, MODE_ENFORCE, MODE_REDACT
from sentinel.models import SystemType
from sentinel.remediation.proxy_gateway import ProxyGateway
from sentinel.remediation.policy_generator import PolicyGenerator
from sentinel.remediation.remediator import Remediator

class TestGateway(unittest.TestCase):

    def setUp(self):
        init_db(force_reseed=True)

    def test_proxy_monitor_mode(self):
        set_proxy_mode(MODE_MONITOR)
        # ArgoCD token calling delete in MONITOR mode:
        token = "hrbr_sec_9941a87b1c3e4492a8392110c"
        code, body = ProxyGateway.process_request(
            SystemType.HARBOR, token, "DELETE", "/api/v2.0/projects/prod-apps/repositories/frontend"
        )
        # In monitor mode, since token originally possessed repository:delete, it passes
        self.assertEqual(code, 200)

    def test_proxy_enforce_mode_after_remediation(self):
        token = "hrbr_sec_9941a87b1c3e4492a8392110c"
        cred_id = "cred_harbor_argo_001"

        # Apply least-privilege plan (down-scopes to repository:pull)
        plan = PolicyGenerator.generate_plan(cred_id)
        Remediator.apply_plan(plan.id)

        # Enable ENFORCE mode
        set_proxy_mode(MODE_ENFORCE)

        # Pull request should be allowed
        code, body = ProxyGateway.process_request(
            SystemType.HARBOR, token, "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts"
        )
        self.assertEqual(code, 200)

        # Delete request should be BLOCKED by Sentinel Gateway!
        code_del, body_del = ProxyGateway.process_request(
            SystemType.HARBOR, token, "DELETE", "/api/v2.0/projects/prod-apps/repositories/frontend"
        )
        self.assertEqual(code_del, 403)
        self.assertIn("BLOCKED", str(body_del))

    def test_proxy_redact_mode(self):
        set_proxy_mode(MODE_REDACT)
        finch_token = "fnch_tok_live_89f3a12948b84931bcfa8723"
        code, body = ProxyGateway.process_request(
            SystemType.FINCH, finch_token, "GET", "/employer/pay-statement"
        )
        self.assertEqual(code, 200)
        statements = body.get("pay_statements", [])
        self.assertGreater(len(statements), 0)
        self.assertEqual(statements[0]["ssn"], "[REDACTED_SSN]")
        self.assertEqual(statements[0]["annual_salary_usd"], "[REDACTED_COMPENSATION]")

if __name__ == "__main__":
    unittest.main()
