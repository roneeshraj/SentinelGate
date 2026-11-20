"""
Gap Analyzer for SentinelGate.
Compares granted scopes vs actual runtime usage to compute excess privilege ratio and risk scores.
"""

from typing import Dict, Any, List, Optional
from sentinel.config import SCOPE_RISK_WEIGHTS
from sentinel.models import RiskLevel, SystemType, ScopeAudit
from sentinel.database import (
    get_credential_by_id,
    get_observed_scopes_for_cred,
    get_access_logs
)

class GapAnalyzer:
    """Analyzes the divergence between granted permissions and actual observed usage."""

    @staticmethod
    def audit_credential(cred_id: str) -> Optional[ScopeAudit]:
        cred = get_credential_by_id(cred_id)
        if not cred:
            return None

        granted = set(cred["granted_scopes"])
        observed = set(get_observed_scopes_for_cred(cred_id))
        
        # Ensure observed is a subset of granted (or flag unauthorized attempts)
        legit_observed = observed.intersection(granted)
        unused = granted - legit_observed

        total_granted = len(granted)
        total_unused = len(unused)
        excess_ratio = (total_unused / total_granted * 100.0) if total_granted > 0 else 0.0

        # Calculate Risk Score
        # Accumulate weights of unused scopes
        raw_risk = sum(SCOPE_RISK_WEIGHTS.get(scope, 10.0) for scope in unused)
        # Normalize to 0 - 100 scale
        risk_score = min(100.0, raw_risk)

        # Classify Risk Level
        if risk_score >= 75.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 50.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 25.0:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Identify Specific Threat Vectors
        threat_vectors = []
        system_type = SystemType(cred["system_type"])

        if system_type == SystemType.FINCH:
            if "payment:write" in unused:
                threat_vectors.append("Financial Manipulation: Dormant ability to execute unauthorized payroll disbursements.")
            if "ssn:read" in unused:
                threat_vectors.append("Identity Theft: Exposure of unmasked Social Security Numbers across all employees.")
            if "pay_statement:read" in unused:
                threat_vectors.append("Executive Compensation Leak: Unauthorized exfiltration of salary and wage data.")
            if "individual:read" in unused:
                threat_vectors.append("PII Exposure: Unnecessary access to private home addresses and personal telephone numbers.")
            if "benefits:write" in unused:
                threat_vectors.append("Benefits Tampering: Ability to alter health and 401(k) election records.")
        else: # HARBOR
            if "system:admin" in unused:
                threat_vectors.append("Registry Takeover: Catastrophic superuser privilege granted to an external tool.")
            if "webhook:manage" in unused:
                threat_vectors.append("Supply Chain Interception: External control over webhook endpoints and artifact push notifications.")
            if "repository:delete" in unused or "artifact:delete" in unused:
                threat_vectors.append("Production Registry Sabotage: Deletion of critical production container repositories.")
            if "scanner:configure" in unused:
                threat_vectors.append("Security Gate Bypass: Ability to disable automated Trivy vulnerability scanning.")
            if "repository:push" in unused:
                threat_vectors.append("Image Tampering: Privilege to push untrusted container layers into release streams.")

        # Total calls
        logs = get_access_logs(cred_id, limit=1000)
        total_calls = len(logs)

        # Placeholder for demonstration & blast radius (populated by blast_radius.py & demonstrator.py)
        audit = ScopeAudit(
            credential_id=cred["id"],
            client_id=cred["client_id"],
            client_name=cred["client_name"],
            system_type=system_type,
            granted_scopes=sorted(list(granted)),
            observed_scopes=sorted(list(legit_observed)),
            unused_scopes=sorted(list(unused)),
            excess_ratio=excess_ratio,
            risk_score=risk_score,
            risk_level=risk_level,
            total_calls=total_calls,
            threat_vectors=threat_vectors,
            demonstration_exploit={},
            blast_radius_nodes=[],
            blast_radius_edges=[]
        )
        return audit
