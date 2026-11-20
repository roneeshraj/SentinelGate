"""
Blast Radius Generator for SentinelGate.
Models graph relationships: Token -> Scopes -> Target Data Assets -> Exploit Impacts.
"""

from typing import Dict, Any, List, Tuple
from sentinel.models import SystemType, ScopeAudit
from sentinel.config import DATA_CLASSIFICATION

class BlastRadiusModeler:
    """Generates graph structures for visualizing the blast radius of overprivileged API credentials."""

    @staticmethod
    def generate_graph(audit: ScopeAudit) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        nodes = []
        edges = []

        # 1. Root Node: The Third-Party Integration Token
        root_id = f"token_{audit.credential_id}"
        nodes.append({
            "id": root_id,
            "label": f"Token: {audit.client_name}",
            "type": "TOKEN",
            "risk": audit.risk_level.value,
            "description": f"Granted {len(audit.granted_scopes)} scopes | Used: {len(audit.observed_scopes)}"
        })

        # 2. Intermediate Nodes: Scopes (Categorized by Used vs Excessive)
        for scope in audit.granted_scopes:
            is_unused = scope in audit.unused_scopes
            scope_id = f"scope_{scope}"
            nodes.append({
                "id": scope_id,
                "label": scope,
                "type": "EXCESS_SCOPE" if is_unused else "LEGIT_SCOPE",
                "risk": "HIGH" if is_unused else "LOW",
                "description": "UNUSED / EXCESS PRIVILEGE" if is_unused else "ACTIVE OPERATIONAL SCOPE"
            })
            edges.append({
                "source": root_id,
                "target": scope_id,
                "relation": "grants",
                "style": "dashed" if is_unused else "solid"
            })

        # 3. Leaf Nodes: Assets and Exploitation Blast Impacts
        if audit.system_type == SystemType.FINCH:
            if "ssn:read" in audit.unused_scopes:
                asset_id = "asset_ssn"
                nodes.append({
                    "id": asset_id,
                    "label": "142 Employee SSNs & Tax IDs",
                    "type": "EXPOSED_ASSET",
                    "risk": "CRITICAL",
                    "description": "Sensitive Federal Tax Identifiers"
                })
                edges.append({"source": "scope_ssn:read", "target": asset_id, "relation": "exposes"})

            if "pay_statement:read" in audit.unused_scopes:
                asset_id = "asset_salaries"
                nodes.append({
                    "id": asset_id,
                    "label": "Executive & Staff Salary Records",
                    "type": "EXPOSED_ASSET",
                    "risk": "HIGH",
                    "description": "$1.2M Annual Payroll Ledger"
                })
                edges.append({"source": "scope_pay_statement:read", "target": asset_id, "relation": "exposes"})

            if "payment:write" in audit.unused_scopes:
                asset_id = "threat_wire_tampering"
                nodes.append({
                    "id": asset_id,
                    "label": "Direct Deposit Wire Manipulation",
                    "type": "THREAT_IMPACT",
                    "risk": "CRITICAL",
                    "description": "Ability to divert payroll funds to offshore accounts"
                })
                edges.append({"source": "scope_payment:write", "target": asset_id, "relation": "enables"})

            if "individual:read" in audit.unused_scopes:
                asset_id = "asset_home_addresses"
                nodes.append({
                    "id": asset_id,
                    "label": "Home Addresses & Personal Cellphones",
                    "type": "EXPOSED_ASSET",
                    "risk": "MEDIUM",
                    "description": "Physical location PII data"
                })
                edges.append({"source": "scope_individual:read", "target": asset_id, "relation": "exposes"})

        else: # HARBOR
            if "system:admin" in audit.unused_scopes:
                asset_id = "threat_root_takeover"
                nodes.append({
                    "id": asset_id,
                    "label": "Full Harbor Registry Control",
                    "type": "THREAT_IMPACT",
                    "risk": "CRITICAL",
                    "description": "Superuser control across all enterprise projects"
                })
                edges.append({"source": "scope_system:admin", "target": asset_id, "relation": "enables"})

            if "repository:delete" in audit.unused_scopes:
                asset_id = "asset_prod_images"
                nodes.append({
                    "id": asset_id,
                    "label": "Prod Repositories: frontend, backend, auth",
                    "type": "EXPOSED_ASSET",
                    "risk": "HIGH",
                    "description": "Production container images at risk of deletion"
                })
                edges.append({"source": "scope_repository:delete", "target": asset_id, "relation": "threatens"})

            if "repository:push" in audit.unused_scopes:
                asset_id = "threat_trojan_image"
                nodes.append({
                    "id": asset_id,
                    "label": "Backdoored Container Injection",
                    "type": "THREAT_IMPACT",
                    "risk": "HIGH",
                    "description": "Attacker can overwrite prod:latest tag with malware"
                })
                edges.append({"source": "scope_repository:push", "target": asset_id, "relation": "enables"})

            if "webhook:manage" in audit.unused_scopes:
                asset_id = "threat_webhook_hijack"
                nodes.append({
                    "id": asset_id,
                    "label": "CI/CD Pipeline Webhook Exfiltration",
                    "type": "THREAT_IMPACT",
                    "risk": "HIGH",
                    "description": "Build notifications rerouted to attacker endpoints"
                })
                edges.append({"source": "scope_webhook:manage", "target": asset_id, "relation": "enables"})

        return nodes, edges
