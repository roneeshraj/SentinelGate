"""
Unit tests for Harbor Container Registry integration and permissions.
"""

import unittest
from sentinel.harbor_system.harbor_permissions import resolve_harbor_scope, HARBOR_SCOPES
from sentinel.harbor_system.mock_harbor import MockHarborEngine
from sentinel.harbor_system.harbor_adapter import HarborAdapter

class TestHarborPermissions(unittest.TestCase):

    def test_scope_resolution(self):
        self.assertEqual(
            resolve_harbor_scope("GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts"),
            "repository:pull"
        )
        self.assertEqual(
            resolve_harbor_scope("POST", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts"),
            "repository:push"
        )
        self.assertEqual(
            resolve_harbor_scope("DELETE", "/api/v2.0/projects/prod-apps/repositories/frontend"),
            "repository:delete"
        )
        self.assertEqual(
            resolve_harbor_scope("POST", "/api/v2.0/projects/prod-apps/webhooks"),
            "webhook:manage"
        )

    def test_mock_harbor_authorized(self):
        scopes = ["repository:pull"]
        code, body, matched = MockHarborEngine.handle_request(
            "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts", scopes
        )
        self.assertEqual(code, 200)
        self.assertEqual(matched, "repository:pull")
        self.assertIn("artifacts", body)

    def test_mock_harbor_forbidden(self):
        # Only has pull, attempts delete
        scopes = ["repository:pull"]
        code, body, matched = MockHarborEngine.handle_request(
            "DELETE", "/api/v2.0/projects/prod-apps/repositories/frontend", scopes
        )
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "FORBIDDEN")
        self.assertEqual(matched, "repository:delete")

    def test_harbor_robot_spec_generation(self):
        adapter = HarborAdapter()
        spec = adapter.generate_robot_account_spec(
            "robot$argocd-least-priv", ["repository:pull", "artifact:read"], "prod-apps"
        )
        self.assertEqual(spec["name"], "robot$argocd-least-priv")
        self.assertEqual(len(spec["permissions"][0]["access"]), 2)
        actions = [a["action"] for a in spec["permissions"][0]["access"]]
        self.assertIn("pull", actions)
        self.assertIn("read", actions)

if __name__ == "__main__":
    unittest.main()
