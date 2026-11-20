"""
Mock Harbor v2.0 Container Registry Server and Backend Logic.
Provides mock projects, repos, tags, webhooks, and robot account validation.
"""

from typing import Dict, Any, List, Optional, Tuple
import json
from sentinel.harbor_system.harbor_permissions import resolve_harbor_scope, HARBOR_SCOPES

# Simulated Harbor In-Memory Data Store
MOCK_HARBOR_PROJECTS = {
    "prod-apps": {
        "id": 1,
        "name": "prod-apps",
        "public": False,
        "repo_count": 4,
        "storage_used_gb": 48.5,
        "repositories": {
            "frontend": {
                "name": "prod-apps/frontend",
                "artifacts": [
                    {"tag": "v1.4.2", "digest": "sha256:7b4192ad1c4f", "size_mb": 120, "vulnerabilities": {"critical": 0, "high": 1, "medium": 4}},
                    {"tag": "v1.4.1", "digest": "sha256:e924a1b80cd9", "size_mb": 118, "vulnerabilities": {"critical": 0, "high": 0, "medium": 2}},
                    {"tag": "latest", "digest": "sha256:7b4192ad1c4f", "size_mb": 120, "vulnerabilities": {"critical": 0, "high": 1, "medium": 4}}
                ]
            },
            "backend": {
                "name": "prod-apps/backend",
                "artifacts": [
                    {"tag": "v2.0.0", "digest": "sha256:4a81bc7e10df", "size_mb": 340, "vulnerabilities": {"critical": 0, "high": 2, "medium": 8}},
                    {"tag": "latest", "digest": "sha256:4a81bc7e10df", "size_mb": 340, "vulnerabilities": {"critical": 0, "high": 2, "medium": 8}}
                ]
            },
            "auth-service": {
                "name": "prod-apps/auth-service",
                "artifacts": [
                    {"tag": "v3.1.0", "digest": "sha256:cc99812eef01", "size_mb": 185, "vulnerabilities": {"critical": 0, "high": 0, "medium": 1}}
                ]
            },
            "payment-gateway": {
                "name": "prod-apps/payment-gateway",
                "artifacts": [
                    {"tag": "v1.0.4", "digest": "sha256:8890fa123bb4", "size_mb": 210, "vulnerabilities": {"critical": 0, "high": 0, "medium": 0}}
                ]
            }
        },
        "webhooks": [
            {"id": 101, "name": "Slack Deployment Alerts", "url": "https://hooks.slack.com/services/T00/B00/X00", "event_types": ["push_artifact"]}
        ],
        "scanner": {"id": 1, "name": "Trivy", "is_default": True, "prevent_vuln": True, "severity": "high"}
    }
}

class MockHarborEngine:
    """Handles simulated Harbor requests and checks permissions."""

    @staticmethod
    def handle_request(method: str, path: str, token_scopes: List[str]) -> Tuple[int, Dict[str, Any], str]:
        """
        Executes a mock Harbor API request.
        Returns: (status_code, response_body, matched_scope)
        """
        matched_scope = resolve_harbor_scope(method, path)

        # Superuser bypass
        has_permission = ("system:admin" in token_scopes) or (matched_scope in token_scopes)

        if not has_permission:
            return (
                403,
                {
                    "error": "FORBIDDEN",
                    "message": f"Insufficient Harbor privileges. Action requires scope '{matched_scope}'.",
                    "required_scope": matched_scope,
                    "granted_scopes": token_scopes
                },
                matched_scope
            )

        # Route matching
        method = method.upper()

        if path == "/api/v2.0/projects" and method == "GET":
            projects_summary = [
                {"id": p["id"], "name": p["name"], "public": p["public"], "repo_count": p["repo_count"], "storage_used_gb": p["storage_used_gb"]}
                for p in MOCK_HARBOR_PROJECTS.values()
            ]
            return 200, {"projects": projects_summary}, matched_scope

        elif path == "/api/v2.0/system/health" and method == "GET":
            return 200, {"status": "healthy", "components": {"database": "healthy", "core": "healthy", "redis": "healthy", "registry": "healthy"}}, matched_scope

        elif "/artifacts" in path and method == "GET":
            # List artifacts
            parts = path.strip("/").split("/")
            # /api/v2.0/projects/{project_name}/repositories/{repo_name}/artifacts
            try:
                proj_name = parts[3]
                repo_name = parts[5]
                artifacts = MOCK_HARBOR_PROJECTS[proj_name]["repositories"][repo_name]["artifacts"]
                return 200, {"project": proj_name, "repository": repo_name, "artifacts": artifacts}, matched_scope
            except Exception:
                return 200, {"artifacts": [{"tag": "latest", "digest": "sha256:7b4192ad1c4f"}]}, matched_scope

        elif method == "POST" and "/artifacts" in path:
            return 201, {"status": "created", "message": "Artifact layer pushed successfully", "digest": "sha256:newlayer99482"}, matched_scope

        elif method == "DELETE" and "/artifacts" in path:
            return 200, {"status": "deleted", "message": "Artifact removed from registry"}, matched_scope

        elif method == "DELETE" and "/repositories" in path:
            return 200, {"status": "deleted", "message": "Repository and all artifacts deleted from Harbor"}, matched_scope

        elif method == "POST" and "/webhooks" in path:
            return 201, {"id": 102, "status": "active", "message": "Webhook registered"}, matched_scope

        elif method == "PUT" and "/scanners" in path:
            return 200, {"status": "updated", "message": "Vulnerability scanning policy altered"}, matched_scope

        elif "/system/" in path:
            return 200, {"system_version": "v2.10.0", "admin_mode": True, "auth_mode": "db_auth"}, matched_scope

        return 200, {"status": "ok", "message": "Harbor API action completed"}, matched_scope
