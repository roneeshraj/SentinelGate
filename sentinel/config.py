"""
Configuration and constants for SentinelGate:
Third-Party API Access Security & Least-Privilege Enforcement Platform for Harbor & Finch Systems.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "sentinel.db"
STATIC_DIR = BASE_DIR / "sentinel" / "web" / "static"

# Server Settings
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

# Proxy Enforcement Modes
MODE_MONITOR = "MONITOR"    # Log excessive usage, do not block
MODE_ENFORCE = "ENFORCE"    # Block requests outside least-privilege baseline
MODE_REDACT = "REDACT"      # Redact unauthorized sensitive response fields

# Risk Scoring Weight Configuration (Scope Sensitivity)
SCOPE_RISK_WEIGHTS = {
    # Finch Scopes (HRIS / Payroll / PII)
    "payment:write": 35.0,        # Critical: can trigger/modify salary payouts
    "ssn:read": 30.0,              # Critical: identity theft / sensitive PII
    "pay_statement:read": 25.0,    # High: executive compensation & wage leaks
    "payment:read": 20.0,          # High: financial summary access
    "benefits:write": 25.0,        # High: alter benefit elections
    "benefits:read": 15.0,         # Medium: benefit enrollment data
    "individual:read": 18.0,       # Medium: personal addresses, phone numbers
    "employment:read": 10.0,       # Low-Medium: job titles, start dates
    "directory:read": 5.0,         # Low: work email, name, department
    "company:read": 5.0,           # Low: company name, legal structure
    
    # Harbor Scopes (Container Registry / Artifact Supply Chain)
    "system:admin": 40.0,          # Catastrophic: full registry control
    "webhook:manage": 30.0,        # Critical: redirect build artifacts or exfiltrate tokens
    "scanner:configure": 25.0,     # High: disable vulnerability scanner / alter CVE policy
    "repository:delete": 25.0,     # High: delete production container images
    "project:admin": 25.0,         # High: manipulate project access & quotas
    "repository:push": 20.0,       # High: inject untrusted container images into production
    "artifact:delete": 18.0,       # Medium: delete image tags and digests
    "artifact:read": 8.0,          # Low: read vulnerability reports & metadata
    "repository:pull": 5.0,        # Low: read/pull public or project container images
}

# Blast Radius Sensitivity Classifications
DATA_CLASSIFICATION = {
    "FINANCIAL_WRITE": ["payment:write", "benefits:write"],
    "HIGH_PII": ["ssn:read", "pay_statement:read"],
    "MEDIUM_PII": ["payment:read", "benefits:read", "individual:read"],
    "ORGANIZATIONAL": ["employment:read", "directory:read", "company:read"],
    
    "REGISTRY_CONTROL": ["system:admin", "webhook:manage", "scanner:configure"],
    "CONTAINER_MUTATION": ["repository:push", "repository:delete", "project:admin", "artifact:delete"],
    "CONTAINER_READ": ["repository:pull", "artifact:read"],
}
