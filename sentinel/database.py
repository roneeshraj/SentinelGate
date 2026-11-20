"""
SQLite Database engine for SentinelGate.
Stores third-party clients, credentials, access telemetry, audit results, and remediation plans.
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sentinel.config import DB_PATH, MODE_ENFORCE, MODE_MONITOR, MODE_REDACT
from sentinel.models import (
    SystemType, TokenStatus, RiskLevel,
    ThirdPartyClient, ApiCredential, AccessLog, RemediationPlan
)

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed: bool = False):
    """Initializes tables and seeds baseline data if empty or forced."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if force_reseed:
        cursor.execute("DROP TABLE IF EXISTS access_logs")
        cursor.execute("DROP TABLE IF EXISTS credentials")
        cursor.execute("DROP TABLE IF EXISTS clients")
        cursor.execute("DROP TABLE IF EXISTS remediation_plans")
        cursor.execute("DROP TABLE IF EXISTS proxy_settings")

    # Table: Clients
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        vendor TEXT NOT NULL,
        description TEXT NOT NULL,
        system_type TEXT NOT NULL,
        environment TEXT DEFAULT 'production',
        status TEXT DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL
    )
    """)

    # Table: Credentials
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        system_type TEXT NOT NULL,
        token_name TEXT NOT NULL,
        token_value TEXT NOT NULL,
        granted_scopes TEXT NOT NULL, -- JSON list
        created_at TEXT NOT NULL,
        last_used_at TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        FOREIGN KEY (client_id) REFERENCES clients(id)
    )
    """)

    # Table: Access Logs (Telemetry)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        client_name TEXT NOT NULL,
        system_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        http_method TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        matched_scope TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        blocked INTEGER NOT NULL DEFAULT 0,
        redacted_fields TEXT DEFAULT '[]', -- JSON list
        risk_indicator TEXT,
        FOREIGN KEY (credential_id) REFERENCES credentials(id)
    )
    """)

    # Table: Remediation Plans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_plans (
        id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        client_name TEXT NOT NULL,
        system_type TEXT NOT NULL,
        current_scopes TEXT NOT NULL,     -- JSON list
        recommended_scopes TEXT NOT NULL, -- JSON list
        revoked_scopes TEXT NOT NULL,     -- JSON list
        risk_score_before REAL NOT NULL,
        risk_score_after REAL NOT NULL,
        reduction_percentage REAL NOT NULL,
        policy_harbor_json TEXT,
        policy_finch_json TEXT,
        policy_rego TEXT,
        status TEXT DEFAULT 'PENDING',
        applied_at TEXT,
        FOREIGN KEY (credential_id) REFERENCES credentials(id)
    )
    """)

    # Table: Proxy Configuration
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS proxy_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        mode TEXT DEFAULT 'MONITOR',
        updated_at TEXT NOT NULL
    )
    """)

    # Ensure proxy_settings has default row
    cursor.execute("SELECT id FROM proxy_settings WHERE id = 1")
    if not cursor.fetchone():
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("INSERT INTO proxy_settings (id, mode, updated_at) VALUES (1, ?, ?)", (MODE_MONITOR, now))

    conn.commit()

    # Check if seed data exists
    cursor.execute("SELECT COUNT(*) as count FROM clients")
    count = cursor.fetchone()["count"]
    if count == 0 or force_reseed:
        _seed_realistic_data(conn)

    conn.close()

def _seed_realistic_data(conn: sqlite3.Connection):
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # 1. Finch Clients & Credentials
    finch_clients = [
        (
            "client_finch_slack_bot",
            "Slack Org & Birthday Bot",
            "TeamPulse Integrations",
            "Displays team organizational hierarchy, employee work anniversaries, and birthdays in Slack.",
            "FINCH",
            "production",
            "ACTIVE",
            "2026-08-10T10:00:00Z"
        ),
        (
            "client_finch_expense_hub",
            "ExpensifyPro Travel & Spend",
            "ExpensifyPro SaaS",
            "Synchronizes employee profiles for travel bookings and automated expense receipt reconciliation.",
            "FINCH",
            "production",
            "ACTIVE",
            "2026-09-01T14:30:00Z"
        ),
        (
            "client_finch_benefits_flow",
            "BenefitFlo Enrollment Sync",
            "BenefitFlo Corp",
            "Automates 401(k) and medical benefits enrollment for newly onboarded staff.",
            "FINCH",
            "production",
            "ACTIVE",
            "2026-10-12T09:15:00Z"
        )
    ]

    cursor.executemany("""
    INSERT INTO clients (id, name, vendor, description, system_type, environment, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, finch_clients)

    finch_creds = [
        (
            "cred_finch_slack_001",
            "client_finch_slack_bot",
            "FINCH",
            "Finch OAuth2 Access Token (SlackBot)",
            "fnch_tok_live_89f3a12948b84931bcfa8723",
            json.dumps([
                "company:read",
                "directory:read",
                "individual:read",
                "ssn:read",
                "pay_statement:read",
                "payment:read"
            ]),
            "2026-08-10T10:05:00Z",
            now,
            "ACTIVE"
        ),
        (
            "cred_finch_expense_002",
            "client_finch_expense_hub",
            "FINCH",
            "Finch OAuth2 Access Token (ExpensifyPro)",
            "fnch_tok_live_7c44e99120de3b110acb3211",
            json.dumps([
                "company:read",
                "directory:read",
                "employment:read",
                "payment:read",
                "payment:write",
                "benefits:write"
            ]),
            "2026-09-01T14:35:00Z",
            now,
            "ACTIVE"
        ),
        (
            "cred_finch_benefits_003",
            "client_finch_benefits_flow",
            "FINCH",
            "Finch OAuth2 Access Token (BenefitFlo)",
            "fnch_tok_live_99d14f4422e17ba909871144",
            json.dumps([
                "directory:read",
                "individual:read",
                "benefits:read",
                "benefits:write",
                "ssn:read"
            ]),
            "2026-10-12T09:20:00Z",
            now,
            "ACTIVE"
        )
    ]

    cursor.executemany("""
    INSERT INTO credentials (id, client_id, system_type, token_name, token_value, granted_scopes, created_at, last_used_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, finch_creds)

    # 2. Harbor Clients & Credentials
    harbor_clients = [
        (
            "client_harbor_argo_cd",
            "ArgoCD Cluster Deployer",
            "Cloud Native GitOps Group",
            "Automated Kubernetes GitOps deployer checking image tags and registry manifests.",
            "HARBOR",
            "production",
            "ACTIVE",
            "2026-07-15T08:00:00Z"
        ),
        (
            "client_harbor_sonarqube_scanner",
            "SonarQube Container Inspector",
            "Code Quality Systems",
            "Automated image vulnerability scanning and compliance verification prior to production release.",
            "HARBOR",
            "production",
            "ACTIVE",
            "2026-08-20T11:20:00Z"
        ),
        (
            "client_harbor_prometheus_exporter",
            "Prometheus Registry Exporter",
            "Observability Systems Inc",
            "Pulls metrics on storage quota usage, artifact counts, and registry health for Grafana.",
            "HARBOR",
            "production",
            "ACTIVE",
            "2026-09-10T16:45:00Z"
        )
    ]

    cursor.executemany("""
    INSERT INTO clients (id, name, vendor, description, system_type, environment, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, harbor_clients)

    harbor_creds = [
        (
            "cred_harbor_argo_001",
            "client_harbor_argo_cd",
            "HARBOR",
            "Harbor Robot Account (robot$argocd-deployer)",
            "hrbr_sec_9941a87b1c3e4492a8392110c",
            json.dumps([
                "repository:pull",
                "repository:push",
                "repository:delete",
                "webhook:manage",
                "project:admin",
                "system:admin"
            ]),
            "2026-07-15T08:10:00Z",
            now,
            "ACTIVE"
        ),
        (
            "cred_harbor_sonar_002",
            "client_harbor_sonarqube_scanner",
            "HARBOR",
            "Harbor Robot Account (robot$sonarqube-audit)",
            "hrbr_sec_33bb719002ac1f8876123491e",
            json.dumps([
                "repository:pull",
                "artifact:read",
                "repository:delete",
                "scanner:configure"
            ]),
            "2026-08-20T11:25:00Z",
            now,
            "ACTIVE"
        ),
        (
            "cred_harbor_prom_003",
            "client_harbor_prometheus_exporter",
            "HARBOR",
            "Harbor Robot Account (robot$prom-metrics)",
            "hrbr_sec_55ee883100ca4a9911928372d",
            json.dumps([
                "artifact:read",
                "project:admin"
            ]),
            "2026-09-10T16:50:00Z",
            now,
            "ACTIVE"
        )
    ]

    cursor.executemany("""
    INSERT INTO credentials (id, client_id, system_type, token_name, token_value, granted_scopes, created_at, last_used_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, harbor_creds)

    # 3. Seed Realistic Runtime Access Logs (Showing what was used vs unused)
    logs = [
        # Slack Bot: repeatedly accesses directory and company, never touched ssn, payment, pay_statement
        ("cred_finch_slack_001", "Slack Org & Birthday Bot", "FINCH", "2026-11-18T08:12:01Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),
        ("cred_finch_slack_001", "Slack Org & Birthday Bot", "FINCH", "2026-11-18T10:14:22Z", "GET", "/employer/company", "company:read", 200, 0, "[]", None),
        ("cred_finch_slack_001", "Slack Org & Birthday Bot", "FINCH", "2026-11-19T09:00:15Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),
        ("cred_finch_slack_001", "Slack Org & Birthday Bot", "FINCH", "2026-11-19T14:32:40Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),
        ("cred_finch_slack_001", "Slack Org & Birthday Bot", "FINCH", "2026-11-20T00:15:10Z", "GET", "/employer/company", "company:read", 200, 0, "[]", None),

        # Expensify: accesses directory and employment, never calls payment:write or benefits:write
        ("cred_finch_expense_002", "ExpensifyPro Travel & Spend", "FINCH", "2026-11-17T11:00:00Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),
        ("cred_finch_expense_002", "ExpensifyPro Travel & Spend", "FINCH", "2026-11-18T15:20:11Z", "GET", "/employer/employment", "employment:read", 200, 0, "[]", None),
        ("cred_finch_expense_002", "ExpensifyPro Travel & Spend", "FINCH", "2026-11-19T16:11:30Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),

        # BenefitFlo: accesses directory and benefits, occasionally individual
        ("cred_finch_benefits_003", "BenefitFlo Enrollment Sync", "FINCH", "2026-11-16T12:00:00Z", "GET", "/employer/directory", "directory:read", 200, 0, "[]", None),
        ("cred_finch_benefits_003", "BenefitFlo Enrollment Sync", "FINCH", "2026-11-18T14:00:00Z", "GET", "/employer/benefits", "benefits:read", 200, 0, "[]", None),
        ("cred_finch_benefits_003", "BenefitFlo Enrollment Sync", "FINCH", "2026-11-19T10:00:00Z", "POST", "/employer/benefits", "benefits:write", 200, 0, "[]", None),

        # ArgoCD: only pulls artifacts/tags, never pushed, deleted, or touched webhooks/admin
        ("cred_harbor_argo_001", "ArgoCD Cluster Deployer", "HARBOR", "2026-11-18T06:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts", "repository:pull", 200, 0, "[]", None),
        ("cred_harbor_argo_001", "ArgoCD Cluster Deployer", "HARBOR", "2026-11-18T12:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/backend/artifacts", "repository:pull", 200, 0, "[]", None),
        ("cred_harbor_argo_001", "ArgoCD Cluster Deployer", "HARBOR", "2026-11-19T06:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/auth-service/artifacts", "repository:pull", 200, 0, "[]", None),
        ("cred_harbor_argo_001", "ArgoCD Cluster Deployer", "HARBOR", "2026-11-19T18:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts", "repository:pull", 200, 0, "[]", None),

        # SonarQube: pulls artifacts and reads scan reports, never deleted or reconfigured scanner
        ("cred_harbor_sonar_002", "SonarQube Container Inspector", "HARBOR", "2026-11-17T09:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts", "repository:pull", 200, 0, "[]", None),
        ("cred_harbor_sonar_002", "SonarQube Container Inspector", "HARBOR", "2026-11-18T09:00:00Z", "GET", "/api/v2.0/projects/prod-apps/repositories/backend/artifacts/sha256:4a81b/vulnerabilities", "artifact:read", 200, 0, "[]", None),

        # Prometheus: reads system health
        ("cred_harbor_prom_003", "Prometheus Registry Exporter", "HARBOR", "2026-11-19T12:00:00Z", "GET", "/api/v2.0/system/health", "artifact:read", 200, 0, "[]", None),
    ]

    cursor.executemany("""
    INSERT INTO access_logs (credential_id, client_name, system_type, timestamp, http_method, endpoint, matched_scope, status_code, blocked, redacted_fields, risk_indicator)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, logs)

    conn.commit()

# Access methods
def get_all_clients() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM clients ORDER BY system_type, name").fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_client_by_id(client_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_credentials() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("""
    SELECT c.*, cl.name as client_name, cl.vendor, cl.description as client_description, cl.environment
    FROM credentials c
    JOIN clients cl ON c.client_id = cl.id
    ORDER BY c.system_type, cl.name
    """).fetchall()
    conn.close()
    results = []
    for row in rows:
        d = dict(row)
        d["granted_scopes"] = json.loads(d["granted_scopes"])
        d["token_masked"] = f"{d['token_value'][:4]}...{d['token_value'][-4:]}" if len(d["token_value"]) > 8 else "****"
        results.append(d)
    return results

def get_credential_by_id(cred_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("""
    SELECT c.*, cl.name as client_name, cl.vendor, cl.description as client_description, cl.environment
    FROM credentials c
    JOIN clients cl ON c.client_id = cl.id
    WHERE c.id = ?
    """, (cred_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["granted_scopes"] = json.loads(d["granted_scopes"])
    d["token_masked"] = f"{d['token_value'][:4]}...{d['token_value'][-4:]}" if len(d["token_value"]) > 8 else "****"
    return d

def get_credential_by_token(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("""
    SELECT c.*, cl.name as client_name, cl.vendor, cl.description as client_description
    FROM credentials c
    JOIN clients cl ON c.client_id = cl.id
    WHERE c.token_value = ?
    """, (token,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["granted_scopes"] = json.loads(d["granted_scopes"])
    return d

def update_credential_scopes(cred_id: str, new_scopes: List[str], status: str = "REMEDIATED"):
    conn = get_db_connection()
    conn.execute("""
    UPDATE credentials
    SET granted_scopes = ?, status = ?
    WHERE id = ?
    """, (json.dumps(new_scopes), status, cred_id))
    conn.commit()
    conn.close()

def record_access_log(
    credential_id: str,
    client_name: str,
    system_type: str,
    http_method: str,
    endpoint: str,
    matched_scope: str,
    status_code: int,
    blocked: bool = False,
    redacted_fields: Optional[List[str]] = None,
    risk_indicator: Optional[str] = None
):
    conn = get_db_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    INSERT INTO access_logs (
        credential_id, client_name, system_type, timestamp,
        http_method, endpoint, matched_scope, status_code,
        blocked, redacted_fields, risk_indicator
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        credential_id, client_name, system_type, now,
        http_method, endpoint, matched_scope, status_code,
        1 if blocked else 0, json.dumps(redacted_fields or []),
        risk_indicator
    ))
    conn.execute("UPDATE credentials SET last_used_at = ? WHERE id = ?", (now, credential_id))
    conn.commit()
    conn.close()

def get_access_logs(credential_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if credential_id:
        rows = conn.execute("""
        SELECT * FROM access_logs
        WHERE credential_id = ?
        ORDER BY id DESC LIMIT ?
        """, (credential_id, limit)).fetchall()
    else:
        rows = conn.execute("""
        SELECT * FROM access_logs
        ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        d["redacted_fields"] = json.loads(d["redacted_fields"])
        d["blocked"] = bool(d["blocked"])
        res.append(d)
    return res

def get_observed_scopes_for_cred(cred_id: str) -> List[str]:
    conn = get_db_connection()
    rows = conn.execute("""
    SELECT DISTINCT matched_scope
    FROM access_logs
    WHERE credential_id = ? AND blocked = 0
    """, (cred_id,)).fetchall()
    conn.close()
    return [r["matched_scope"] for r in rows if r["matched_scope"]]

def get_proxy_mode() -> str:
    conn = get_db_connection()
    row = conn.execute("SELECT mode FROM proxy_settings WHERE id = 1").fetchone()
    conn.close()
    return row["mode"] if row else MODE_MONITOR

def set_proxy_mode(mode: str):
    conn = get_db_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE proxy_settings SET mode = ?, updated_at = ? WHERE id = 1", (mode, now))
    conn.commit()
    conn.close()

def save_remediation_plan(plan: RemediationPlan):
    conn = get_db_connection()
    conn.execute("""
    INSERT OR REPLACE INTO remediation_plans (
        id, credential_id, client_name, system_type,
        current_scopes, recommended_scopes, revoked_scopes,
        risk_score_before, risk_score_after, reduction_percentage,
        policy_harbor_json, policy_finch_json, policy_rego,
        status, applied_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        plan.id, plan.credential_id, plan.client_name, plan.system_type.value,
        json.dumps(plan.current_scopes), json.dumps(plan.recommended_scopes),
        json.dumps(plan.revoked_scopes), plan.risk_score_before, plan.risk_score_after,
        plan.reduction_percentage,
        json.dumps(plan.policy_harbor_json) if plan.policy_harbor_json else None,
        json.dumps(plan.policy_finch_json) if plan.policy_finch_json else None,
        plan.policy_rego, plan.status, plan.applied_at
    ))
    conn.commit()
    conn.close()

def get_all_remediation_plans() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM remediation_plans ORDER BY id DESC").fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        d["current_scopes"] = json.loads(d["current_scopes"])
        d["recommended_scopes"] = json.loads(d["recommended_scopes"])
        d["revoked_scopes"] = json.loads(d["revoked_scopes"])
        if d["policy_harbor_json"]:
            d["policy_harbor_json"] = json.loads(d["policy_harbor_json"])
        if d["policy_finch_json"]:
            d["policy_finch_json"] = json.loads(d["policy_finch_json"])
        res.append(d)
    return res

def get_remediation_plan_by_id(plan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM remediation_plans WHERE id = ?", (plan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["current_scopes"] = json.loads(d["current_scopes"])
    d["recommended_scopes"] = json.loads(d["recommended_scopes"])
    d["revoked_scopes"] = json.loads(d["revoked_scopes"])
    if d["policy_harbor_json"]:
        d["policy_harbor_json"] = json.loads(d["policy_harbor_json"])
    if d["policy_finch_json"]:
        d["policy_finch_json"] = json.loads(d["policy_finch_json"])
    return d
