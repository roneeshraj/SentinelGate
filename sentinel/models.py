"""
Data models for SentinelGate.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
import json

class SystemType(str, Enum):
    HARBOR = "HARBOR"
    FINCH = "FINCH"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class TokenStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REMEDIATED = "REMEDIATED"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"

class EnforcementMode(str, Enum):
    MONITOR = "MONITOR"
    ENFORCE = "ENFORCE"
    REDACT = "REDACT"

@dataclass
class ThirdPartyClient:
    id: str
    name: str
    vendor: str
    description: str
    system_type: SystemType
    environment: str = "production"
    status: TokenStatus = TokenStatus.ACTIVE
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "description": self.description,
            "system_type": self.system_type.value,
            "environment": self.environment,
            "status": self.status.value,
            "created_at": self.created_at,
        }

@dataclass
class ApiCredential:
    id: str
    client_id: str
    system_type: SystemType
    token_name: str
    token_value: str
    granted_scopes: List[str]
    created_at: str
    last_used_at: str
    status: TokenStatus = TokenStatus.ACTIVE

    @property
    def token_masked(self) -> str:
        if len(self.token_value) <= 8:
            return "****"
        return f"{self.token_value[:4]}...{self.token_value[-4:]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "client_id": self.client_id,
            "system_type": self.system_type.value,
            "token_name": self.token_name,
            "token_masked": self.token_masked,
            "granted_scopes": self.granted_scopes,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "status": self.status.value,
        }

@dataclass
class AccessLog:
    id: int
    credential_id: str
    client_name: str
    system_type: SystemType
    timestamp: str
    http_method: str
    endpoint: str
    matched_scope: str
    status_code: int
    blocked: bool
    redacted_fields: List[str] = field(default_factory=list)
    risk_indicator: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "credential_id": self.credential_id,
            "client_name": self.client_name,
            "system_type": self.system_type.value,
            "timestamp": self.timestamp,
            "http_method": self.http_method,
            "endpoint": self.endpoint,
            "matched_scope": self.matched_scope,
            "status_code": self.status_code,
            "blocked": self.blocked,
            "redacted_fields": self.redacted_fields,
            "risk_indicator": self.risk_indicator,
        }

@dataclass
class BlastRadiusNode:
    id: str
    label: str
    category: str  # client, system, scope, asset, threat
    risk_level: str
    description: str

@dataclass
class BlastRadiusEdge:
    source: str
    target: str
    relation: str

@dataclass
class ScopeAudit:
    credential_id: str
    client_id: str
    client_name: str
    system_type: SystemType
    granted_scopes: List[str]
    observed_scopes: List[str]
    unused_scopes: List[str]
    excess_ratio: float           # 0.0 to 100.0 %
    risk_score: float             # 0.0 to 100.0
    risk_level: RiskLevel
    total_calls: int
    threat_vectors: List[str]
    demonstration_exploit: Dict[str, Any]
    blast_radius_nodes: List[Dict[str, Any]] = field(default_factory=list)
    blast_radius_edges: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "system_type": self.system_type.value,
            "granted_scopes": self.granted_scopes,
            "observed_scopes": self.observed_scopes,
            "unused_scopes": self.unused_scopes,
            "excess_ratio": round(self.excess_ratio, 1),
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value,
            "total_calls": self.total_calls,
            "threat_vectors": self.threat_vectors,
            "demonstration_exploit": self.demonstration_exploit,
            "blast_radius_nodes": self.blast_radius_nodes,
            "blast_radius_edges": self.blast_radius_edges,
        }

@dataclass
class RemediationPlan:
    id: str
    credential_id: str
    client_name: str
    system_type: SystemType
    current_scopes: List[str]
    recommended_scopes: List[str]
    revoked_scopes: List[str]
    risk_score_before: float
    risk_score_after: float
    reduction_percentage: float
    policy_harbor_json: Optional[Dict[str, Any]] = None
    policy_finch_json: Optional[Dict[str, Any]] = None
    policy_rego: Optional[str] = None
    status: str = "PENDING"
    applied_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "credential_id": self.credential_id,
            "client_name": self.client_name,
            "system_type": self.system_type.value,
            "current_scopes": self.current_scopes,
            "recommended_scopes": self.recommended_scopes,
            "revoked_scopes": self.revoked_scopes,
            "risk_score_before": round(self.risk_score_before, 1),
            "risk_score_after": round(self.risk_score_after, 1),
            "reduction_percentage": round(self.reduction_percentage, 1),
            "policy_harbor_json": self.policy_harbor_json,
            "policy_finch_json": self.policy_finch_json,
            "policy_rego": self.policy_rego,
            "status": self.status,
            "applied_at": self.applied_at,
        }
