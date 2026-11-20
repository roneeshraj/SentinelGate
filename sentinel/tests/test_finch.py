"""
Unit tests for Finch Employment API integration, scopes, and PII masking.
"""

import unittest
from sentinel.finch_system.finch_permissions import resolve_finch_scope, FINCH_SCOPES
from sentinel.finch_system.mock_finch import MockFinchEngine
from sentinel.finch_system.finch_adapter import FinchAdapter

class TestFinchPermissions(unittest.TestCase):

    def test_scope_resolution(self):
        self.assertEqual(resolve_finch_scope("GET", "/employer/directory"), "directory:read")
        self.assertEqual(resolve_finch_scope("GET", "/employer/pay-statement"), "pay_statement:read")
        self.assertEqual(resolve_finch_scope("POST", "/employer/payment"), "payment:write")
        self.assertEqual(resolve_finch_scope("POST", "/employer/benefits"), "benefits:write")

    def test_mock_finch_authorized_directory(self):
        scopes = ["directory:read"]
        code, body, matched, _ = MockFinchEngine.handle_request("GET", "/employer/directory", scopes)
        self.assertEqual(code, 200)
        self.assertEqual(matched, "directory:read")
        self.assertIn("directory", body)
        self.assertGreater(len(body["directory"]), 0)

    def test_mock_finch_forbidden_salary_access(self):
        # Slack bot only has directory:read, tries to access pay-statement
        scopes = ["directory:read"]
        code, body, matched, _ = MockFinchEngine.handle_request("GET", "/employer/pay-statement", scopes)
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "FORBIDDEN")
        self.assertEqual(matched, "pay_statement:read")

    def test_mock_finch_redaction_mode(self):
        # Has pay_statement:read, but request is made with mask_sensitive_pii=True
        scopes = ["pay_statement:read", "ssn:read"]
        code, body, matched, redacted = MockFinchEngine.handle_request(
            "GET", "/employer/pay-statement", scopes, mask_sensitive_pii=True
        )
        self.assertEqual(code, 200)
        first_statement = body["pay_statements"][0]
        self.assertEqual(first_statement["annual_salary_usd"], "[REDACTED_COMPENSATION]")
        self.assertEqual(first_statement["ssn"], "[REDACTED_SSN]")
        self.assertIn("ssn", redacted)
        self.assertIn("annual_salary_usd", redacted)

    def test_finch_oauth_spec_generation(self):
        adapter = FinchAdapter()
        spec = adapter.generate_oauth_scope_spec("client_finch_slack_bot", ["company:read", "directory:read"])
        self.assertEqual(spec["client_id"], "client_finch_slack_bot")
        self.assertEqual(spec["auth_url_query_param"], "company:read directory:read")

if __name__ == "__main__":
    unittest.main()
