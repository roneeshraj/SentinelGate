"""
Permission Demonstrator for SentinelGate.
Safely demonstrates how over-privileged tokens can be abused to access sensitive data or perform destructive actions.
"""

from typing import Dict, Any, List, Optional
from sentinel.database import get_credential_by_id
from sentinel.models import SystemType
from sentinel.harbor_system.mock_harbor import MockHarborEngine
from sentinel.finch_system.mock_finch import MockFinchEngine

class PermissionDemonstrator:
    """Executes controlled, safe proof-of-excess demonstrations to visually demonstrate security risk."""

    @staticmethod
    def demonstrate_token_risk(cred_id: str) -> Dict[str, Any]:
        cred = get_credential_by_id(cred_id)
        if not cred:
            return {"error": f"Credential {cred_id} not found"}

        system_type = SystemType(cred["system_type"])
        granted_scopes = cred["granted_scopes"]

        if system_type == SystemType.FINCH:
            return PermissionDemonstrator._demonstrate_finch(cred, granted_scopes)
        else:
            return PermissionDemonstrator._demonstrate_harbor(cred, granted_scopes)

    @staticmethod
    def _demonstrate_finch(cred: Dict[str, Any], granted_scopes: List[str]) -> Dict[str, Any]:
        client_name = cred["client_name"]

        # 1. Legitimate business action
        legit_method = "GET"
        legit_path = "/employer/directory"
        legit_code, legit_body, legit_scope, _ = MockFinchEngine.handle_request(
            legit_method, legit_path, granted_scopes, mask_sensitive_pii=False
        )

        # 2. Excessive capability abuse (demonstration of over-privilege)
        if "pay_statement:read" in granted_scopes:
            exploit_method = "GET"
            exploit_path = "/employer/pay-statement"
            exploit_title = "Unauthorized Executive Salary & Direct Deposit Exfiltration"
            exploit_desc = f"Client '{client_name}' requested only basic directory access, but its token successfully exfiltrates VP of Engineering salary ($260,000) and bank account records via '{exploit_path}'."
        elif "payment:write" in granted_scopes:
            exploit_method = "POST"
            exploit_path = "/employer/payment"
            exploit_title = "Unauthorized Payroll Payment Initiation"
            exploit_desc = f"Client '{client_name}' was granted 'payment:write', allowing an attacker with this token to initiate unvetted off-cycle cash disbursements."
        elif "ssn:read" in granted_scopes:
            exploit_method = "GET"
            exploit_path = "/employer/individual"
            exploit_title = "Unmasked Social Security Number Harvesting"
            exploit_desc = f"Token permits reading unmasked government Social Security Numbers and home addresses."
        else:
            exploit_method = "GET"
            exploit_path = "/employer/employment"
            exploit_title = "Employment Status Inspection"
            exploit_desc = "Access to confidential employee tenure and internal job title levels."

        exploit_code, exploit_body, exploit_scope, _ = MockFinchEngine.handle_request(
            exploit_method, exploit_path, granted_scopes, mask_sensitive_pii=False
        )

        return {
            "credential_id": cred["id"],
            "client_name": client_name,
            "system_type": "FINCH",
            "token_masked": cred["token_masked"],
            "granted_scopes": granted_scopes,
            "legitimate_request": {
                "method": legit_method,
                "endpoint": legit_path,
                "scope_used": legit_scope,
                "status_code": legit_code,
                "sample_response": legit_body,
                "description": "Standard business operation (e.g. employee directory lookups for Slack/Travel)."
            },
            "excessive_demonstration": {
                "title": exploit_title,
                "method": exploit_method,
                "endpoint": exploit_path,
                "scope_abused": exploit_scope,
                "status_code": exploit_code,
                "sample_response": exploit_body,
                "risk_analysis": exploit_desc,
                "exploit_allowed": exploit_code < 400
            }
        }

    @staticmethod
    def _demonstrate_harbor(cred: Dict[str, Any], granted_scopes: List[str]) -> Dict[str, Any]:
        client_name = cred["client_name"]

        # 1. Legitimate business action
        legit_method = "GET"
        legit_path = "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts"
        legit_code, legit_body, legit_scope = MockHarborEngine.handle_request(
            legit_method, legit_path, granted_scopes
        )

        # 2. Excessive capability abuse
        if "system:admin" in granted_scopes:
            exploit_method = "GET"
            exploit_path = "/api/v2.0/system/users"
            exploit_title = "Full Registry System Admin Takeover"
            exploit_desc = f"Robot account possesses 'system:admin' superuser credentials, enabling full administrative control across all projects and system settings."
        elif "webhook:manage" in granted_scopes:
            exploit_method = "POST"
            exploit_path = "/api/v2.0/projects/prod-apps/webhooks"
            exploit_title = "CI/CD Webhook Interception & Token Exfiltration"
            exploit_desc = f"Token permits creating custom registry webhooks, enabling an adversary to capture push notifications and secret payload headers."
        elif "repository:delete" in granted_scopes:
            exploit_method = "DELETE"
            exploit_path = "/api/v2.0/projects/prod-apps/repositories/frontend"
            exploit_title = "Production Container Repository Sabotage"
            exploit_desc = f"Token has permission to permanently delete production container repositories and image tags."
        elif "repository:push" in granted_scopes:
            exploit_method = "POST"
            exploit_path = "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts"
            exploit_title = "Untrusted Container Image Injection (Supply Chain Poisoning)"
            exploit_desc = f"Token possesses 'repository:push' rights, allowing injection of backdoored images into production pipelines."
        else:
            exploit_method = "GET"
            exploit_path = "/api/v2.0/system/health"
            exploit_title = "Infrastructure Reconnaissance"
            exploit_desc = "Inspecting internal container registry cluster health and topology."

        exploit_code, exploit_body, exploit_scope = MockHarborEngine.handle_request(
            exploit_method, exploit_path, granted_scopes
        )

        return {
            "credential_id": cred["id"],
            "client_name": client_name,
            "system_type": "HARBOR",
            "token_masked": cred["token_masked"],
            "granted_scopes": granted_scopes,
            "legitimate_request": {
                "method": legit_method,
                "endpoint": legit_path,
                "scope_used": legit_scope,
                "status_code": legit_code,
                "sample_response": legit_body,
                "description": "Standard business operation (e.g. pulling container images or checking tags)."
            },
            "excessive_demonstration": {
                "title": exploit_title,
                "method": exploit_method,
                "endpoint": exploit_path,
                "scope_abused": exploit_scope,
                "status_code": exploit_code,
                "sample_response": exploit_body,
                "risk_analysis": exploit_desc,
                "exploit_allowed": exploit_code < 400
            }
        }
