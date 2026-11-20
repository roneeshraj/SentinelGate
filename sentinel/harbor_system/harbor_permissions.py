"""
Harbor System Permission Definitions and Scope Mappings.
Models CNCF Harbor v2.0 RBAC and Robot Account permissions.
"""

from typing import Dict, Any, List, Tuple

# Harbor Scope Definitions
HARBOR_SCOPES = {
    "repository:pull": {
        "name": "Pull Container Images",
        "description": "Read and download container images and manifests from repositories.",
        "risk_weight": 5.0,
        "category": "READ",
        "risk_implication": "Low risk; allows inspecting images."
    },
    "artifact:read": {
        "name": "Read Artifacts & Vulnerabilities",
        "description": "Read artifact digests, SBOMs, and CVE security scanning reports.",
        "risk_weight": 8.0,
        "category": "READ",
        "risk_implication": "Low-Medium risk; exposes internal vulnerability reports."
    },
    "repository:push": {
        "name": "Push Container Images",
        "description": "Upload new container image layers and overwrite non-immutable tags.",
        "risk_weight": 20.0,
        "category": "MUTATION",
        "risk_implication": "HIGH RISK: Attacker can inject backdoored container images into production build pipelines."
    },
    "artifact:delete": {
        "name": "Delete Artifacts & Tags",
        "description": "Delete individual tags, layers, and manifests.",
        "risk_weight": 18.0,
        "category": "MUTATION",
        "risk_implication": "HIGH RISK: Disables deployments and causes denial of service by removing base images."
    },
    "repository:delete": {
        "name": "Delete Repositories",
        "description": "Completely remove container repositories and all nested artifact versions.",
        "risk_weight": 25.0,
        "category": "MUTATION",
        "risk_implication": "HIGH RISK: Irreversible deletion of container repositories across production environments."
    },
    "project:admin": {
        "name": "Project Administration",
        "description": "Configure project members, quotas, storage policies, and immutability rules.",
        "risk_weight": 25.0,
        "category": "ADMIN",
        "risk_implication": "CRITICAL RISK: Can remove image immutability protections and alter role bindings."
    },
    "scanner:configure": {
        "name": "Configure Vulnerability Scanner",
        "description": "Alter CVE scanning schedules, bypass severity block gates, or disable Clair/Trivy.",
        "risk_weight": 25.0,
        "category": "ADMIN",
        "risk_implication": "CRITICAL RISK: Attacker can disable security gates allowing known critical CVEs to be deployed."
    },
    "webhook:manage": {
        "name": "Manage Webhooks & Notification Endpoints",
        "description": "Create, modify, and delete notification webhooks triggered on image events.",
        "risk_weight": 30.0,
        "category": "ADMIN",
        "risk_implication": "CRITICAL RISK: Can exfiltrate push tokens and reroute build triggers to attacker-controlled C2 servers."
    },
    "system:admin": {
        "name": "System Superuser Administrator",
        "description": "Unrestricted administrative control across all projects, configurations, and users.",
        "risk_weight": 40.0,
        "category": "ADMIN",
        "risk_implication": "CATASTROPHIC RISK: Complete takeover of entire container registry infrastructure."
    }
}

# Endpoint to Scope Mapping
ENDPOINT_SCOPE_RULES: List[Tuple[str, str, str]] = [
    # (HTTP_METHOD, ENDPOINT_PATTERN, REQUIRED_SCOPE)
    ("GET", "/api/v2.0/projects", "repository:pull"),
    ("GET", "/api/v2.0/system/health", "artifact:read"),
    ("GET", "/api/v2.0/projects/*/repositories/*/artifacts/*/vulnerabilities", "artifact:read"),
    ("GET", "/api/v2.0/projects/*/repositories/*/artifacts", "repository:pull"),
    ("GET", "/api/v2.0/projects/*/repositories", "repository:pull"),
    ("POST", "/api/v2.0/projects/*/repositories/*/artifacts", "repository:push"),
    ("DELETE", "/api/v2.0/projects/*/repositories/*/artifacts/*", "artifact:delete"),
    ("DELETE", "/api/v2.0/projects/*/repositories/*", "repository:delete"),
    ("POST", "/api/v2.0/projects/*/webhooks", "webhook:manage"),
    ("DELETE", "/api/v2.0/projects/*/webhooks/*", "webhook:manage"),
    ("PUT", "/api/v2.0/scanners/*", "scanner:configure"),
    ("POST", "/api/v2.0/projects/*/robots", "project:admin"),
    ("GET", "/api/v2.0/system/users", "system:admin"),
    ("POST", "/api/v2.0/system/configurations", "system:admin"),
]

def resolve_harbor_scope(method: str, path: str) -> str:
    """Matches a requested HTTP method and path to the required Harbor permission scope."""
    method_upper = method.upper()
    for rule_method, pattern, scope in ENDPOINT_SCOPE_RULES:
        if rule_method != method_upper:
            continue
        
        # Simple glob-like path match
        pattern_parts = pattern.strip("/").split("/")
        path_parts = path.strip("/").split("/")
        
        if len(pattern_parts) != len(path_parts):
            continue
        
        matched = True
        for p_part, actual_part in zip(pattern_parts, path_parts):
            if p_part != "*" and p_part != actual_part:
                matched = False
                break
        
        if matched:
            return scope
            
    # Default fallback heuristics
    if method_upper == "GET":
        return "repository:pull"
    elif method_upper in ("POST", "PUT"):
        return "repository:push"
    elif method_upper == "DELETE":
        return "repository:delete"
    return "project:admin"
