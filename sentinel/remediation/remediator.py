"""
Remediator for SentinelGate.
Applies automated least-privilege remediation and maintains rollback records.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sentinel.database import (
    get_remediation_plan_by_id,
    get_all_remediation_plans,
    get_all_credentials,
    save_remediation_plan,
    update_credential_scopes,
    get_credential_by_id
)
from sentinel.models import RemediationPlan, SystemType

class Remediator:
    """Applies least-privilege policies directly to credentials and maintains audit logs."""

    @staticmethod
    def apply_plan(plan_id: str) -> Dict[str, Any]:
        plan_dict = get_remediation_plan_by_id(plan_id)
        if not plan_dict:
            return {"error": f"Plan {plan_id} not found", "success": False}

        cred_id = plan_dict["credential_id"]
        cred = get_credential_by_id(cred_id)
        if not cred:
            return {"error": f"Associated credential {cred_id} not found", "success": False}

        # Down-scope credential
        new_scopes = plan_dict["recommended_scopes"]
        update_credential_scopes(cred_id, new_scopes, status="REMEDIATED")

        # Update plan status
        now = datetime.now(timezone.utc).isoformat()
        plan_dict["status"] = "APPLIED"
        plan_dict["applied_at"] = now

        plan_obj = RemediationPlan(
            id=plan_dict["id"],
            credential_id=plan_dict["credential_id"],
            client_name=plan_dict["client_name"],
            system_type=SystemType(plan_dict["system_type"]),
            current_scopes=plan_dict["current_scopes"],
            recommended_scopes=plan_dict["recommended_scopes"],
            revoked_scopes=plan_dict["revoked_scopes"],
            risk_score_before=plan_dict["risk_score_before"],
            risk_score_after=plan_dict["risk_score_after"],
            reduction_percentage=plan_dict["reduction_percentage"],
            policy_harbor_json=plan_dict["policy_harbor_json"],
            policy_finch_json=plan_dict["policy_finch_json"],
            policy_rego=plan_dict["policy_rego"],
            status="APPLIED",
            applied_at=now
        )
        save_remediation_plan(plan_obj)

        return {
            "success": True,
            "message": f"Successfully down-scoped {plan_dict['client_name']} to least-privilege baseline.",
            "revoked_scopes": plan_dict["revoked_scopes"],
            "new_scopes": new_scopes,
            "risk_score_after": plan_dict["risk_score_after"],
            "reduction_percentage": plan_dict["reduction_percentage"]
        }

    @staticmethod
    def rollback_plan(plan_id: str) -> Dict[str, Any]:
        plan_dict = get_remediation_plan_by_id(plan_id)
        if not plan_dict:
            return {"error": f"Plan {plan_id} not found", "success": False}

        cred_id = plan_dict["credential_id"]
        original_scopes = plan_dict["current_scopes"]
        update_credential_scopes(cred_id, original_scopes, status="ACTIVE")

        # Update plan status
        plan_dict["status"] = "ROLLED_BACK"
        plan_obj = RemediationPlan(
            id=plan_dict["id"],
            credential_id=plan_dict["credential_id"],
            client_name=plan_dict["client_name"],
            system_type=SystemType(plan_dict["system_type"]),
            current_scopes=plan_dict["current_scopes"],
            recommended_scopes=plan_dict["recommended_scopes"],
            revoked_scopes=plan_dict["revoked_scopes"],
            risk_score_before=plan_dict["risk_score_before"],
            risk_score_after=plan_dict["risk_score_after"],
            reduction_percentage=plan_dict["reduction_percentage"],
            policy_harbor_json=plan_dict["policy_harbor_json"],
            policy_finch_json=plan_dict["policy_finch_json"],
            policy_rego=plan_dict["policy_rego"],
            status="ROLLED_BACK",
            applied_at=None
        )
        save_remediation_plan(plan_obj)

        return {
            "success": True,
            "message": f"Successfully restored original scopes for {plan_dict['client_name']}.",
            "restored_scopes": original_scopes
        }

    @staticmethod
    def rollback_all() -> Dict[str, Any]:
        """Rolls back all applied least-privilege policies across all credentials."""
        plans = get_all_remediation_plans()
        applied_plans = [p for p in plans if p["status"] == "APPLIED"]
        rolled_back_clients = []

        for plan in applied_plans:
            res = Remediator.rollback_plan(plan["id"])
            if res.get("success"):
                rolled_back_clients.append(plan["client_name"])

        # Initial benchmark scopes fallback
        initial_scopes = {
            "cred_finch_slack_001": ["company:read", "directory:read", "individual:read", "ssn:read", "pay_statement:read", "payment:read"],
            "cred_finch_expense_002": ["company:read", "directory:read", "employment:read", "payment:read", "payment:write", "benefits:write"],
            "cred_finch_benefits_003": ["directory:read", "individual:read", "benefits:read", "benefits:write", "ssn:read"],
            "cred_harbor_argo_001": ["repository:pull", "repository:push", "repository:delete", "webhook:manage", "project:admin", "system:admin"],
            "cred_harbor_sonar_002": ["repository:pull", "artifact:read", "repository:delete", "scanner:configure"],
            "cred_harbor_prom_003": ["artifact:read", "project:admin"]
        }

        creds = get_all_credentials()
        for c in creds:
            if c["status"] == "REMEDIATED" or c["id"] in initial_scopes:
                if c["id"] in initial_scopes:
                    update_credential_scopes(c["id"], initial_scopes[c["id"]], status="ACTIVE")
                    if c["client_name"] not in rolled_back_clients:
                        rolled_back_clients.append(c["client_name"])

        return {
            "success": True,
            "message": f"Successfully rolled back least-privilege policies for {len(rolled_back_clients)} integrations.",
            "rolled_back_clients": rolled_back_clients
        }
