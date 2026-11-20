"""
Finch Adapter for SentinelGate.
Audits third-party Finch OAuth connections and generates down-scoped OAuth scope matrices.
"""

from typing import Dict, Any, List, Optional
from sentinel.finch_system.finch_permissions import FINCH_SCOPES, resolve_finch_scope
from sentinel.finch_system.mock_finch import MockFinchEngine

class FinchAdapter:
    """Interacts with Finch Unified API to inspect and manage OAuth application scopes."""

    def __init__(self, endpoint_url: str = "http://localhost:8888/mock/finch"):
        self.endpoint_url = endpoint_url

    def test_request(
        self,
        method: str,
        path: str,
        token_scopes: List[str],
        mask_sensitive_pii: bool = False
    ) -> Dict[str, Any]:
        """Tests an API call directly against the Finch engine."""
        status_code, body, matched_scope, redacted = MockFinchEngine.handle_request(
            method, path, token_scopes, mask_sensitive_pii
        )
        return {
            "status_code": status_code,
            "body": body,
            "matched_scope": matched_scope,
            "redacted_fields": redacted,
            "allowed": status_code < 400
        }

    def generate_oauth_scope_spec(self, client_id: str, allowed_scopes: List[str]) -> Dict[str, Any]:
        """
        Generates a least-privilege Finch Connect OAuth2 configuration.
        """
        return {
            "client_id": client_id,
            "recommended_scopes": allowed_scopes,
            "auth_url_query_param": " ".join(allowed_scopes),
            "enforce_strict_scopes": True,
            "data_access_level": "LEAST_PRIVILEGE",
            "audit_compliance": ["SOC2_TYPE_2", "GDPR_ARTICLE_25", "CCPA"]
        }
