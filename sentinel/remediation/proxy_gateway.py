"""
Proxy Gateway for SentinelGate.
Inline Least-Privilege API Reverse Proxy with scope enforcement and sensitive field redaction.
"""

from typing import Dict, Any, List, Tuple, Optional
from sentinel.config import MODE_ENFORCE, MODE_MONITOR, MODE_REDACT
from sentinel.models import SystemType
from sentinel.database import (
    get_credential_by_token,
    get_proxy_mode,
    record_access_log,
    get_observed_scopes_for_cred
)
from sentinel.harbor_system.mock_harbor import MockHarborEngine
from sentinel.harbor_system.harbor_permissions import resolve_harbor_scope
from sentinel.finch_system.mock_finch import MockFinchEngine
from sentinel.finch_system.finch_permissions import resolve_finch_scope

class ProxyGateway:
    """Interprets and filters incoming third-party API requests before forwarding to target systems."""

    @staticmethod
    def process_request(
        system_type: SystemType,
        token: str,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Processes a proxied third-party API call.
        Returns: (http_status_code, response_payload)
        """
        cred = get_credential_by_token(token)
        if not cred:
            return 401, {
                "error": "UNAUTHORIZED",
                "message": "Invalid API token. No matching third-party integration credential found."
            }

        proxy_mode = get_proxy_mode()
        granted_scopes = cred["granted_scopes"]
        cred_id = cred["id"]
        client_name = cred["client_name"]

        if system_type == SystemType.FINCH:
            matched_scope = resolve_finch_scope(method, path)
        else:
            matched_scope = resolve_harbor_scope(method, path)

        # Baseline check: is this scope part of the known operational baseline?
        observed_scopes = get_observed_scopes_for_cred(cred_id)
        is_outside_baseline = (matched_scope not in observed_scopes) if observed_scopes else False

        # ENFORCEMENT CHECK
        if proxy_mode == MODE_ENFORCE:
            # Under strict ENFORCE mode, block if scope is not granted OR if it exceeds the observed baseline
            if matched_scope not in granted_scopes:
                record_access_log(
                    credential_id=cred_id,
                    client_name=client_name,
                    system_type=system_type.value,
                    http_method=method,
                    endpoint=path,
                    matched_scope=matched_scope,
                    status_code=403,
                    blocked=True,
                    risk_indicator=f"BLOCKED: Scope '{matched_scope}' not granted to client."
                )
                return 403, {
                    "error": "FORBIDDEN",
                    "sentinel_action": "BLOCKED",
                    "reason": f"Scope '{matched_scope}' is not granted to client '{client_name}'."
                }

            if is_outside_baseline:
                record_access_log(
                    credential_id=cred_id,
                    client_name=client_name,
                    system_type=system_type.value,
                    http_method=method,
                    endpoint=path,
                    matched_scope=matched_scope,
                    status_code=403,
                    blocked=True,
                    risk_indicator=f"BLOCKED_BY_LEAST_PRIVILEGE: Scope '{matched_scope}' exceeds least-privilege baseline."
                )
                return 403, {
                    "error": "EXCESSIVE_PERMISSION_BLOCKED",
                    "sentinel_action": "ENFORCED",
                    "reason": f"Access to '{path}' blocked by Sentinel Least-Privilege Gateway. Scope '{matched_scope}' is outside normal operational baseline.",
                    "client": client_name
                }

        # REDACTION MODE: If client requests individual/pay statement, redact sensitive fields
        mask_pii = (proxy_mode == MODE_REDACT)

        # Forward to mock engine
        if system_type == SystemType.FINCH:
            code, resp_body, _, redacted_fields = MockFinchEngine.handle_request(
                method, path, granted_scopes, mask_sensitive_pii=mask_pii
            )
        else:
            code, resp_body, _ = MockHarborEngine.handle_request(method, path, granted_scopes)
            redacted_fields = []

        # Determine risk indicator
        risk_ind = None
        if is_outside_baseline:
            risk_ind = f"ANOMALY: Out-of-baseline access to scope '{matched_scope}'"

        # Record telemetry log
        record_access_log(
            credential_id=cred_id,
            client_name=client_name,
            system_type=system_type.value,
            http_method=method,
            endpoint=path,
            matched_scope=matched_scope,
            status_code=code,
            blocked=False,
            redacted_fields=redacted_fields,
            risk_indicator=risk_ind
        )

        return code, resp_body
