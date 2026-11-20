"""
Remediator for SentinelGate.
Applies automated least-privilege remediation and maintains rollback records.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sentinel.database import (
    get_remediation_plan_by_id,
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
