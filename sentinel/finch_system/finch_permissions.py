"""
Finch System Permission Definitions and Scope Mappings.
Models Finch Unified API for Employment Systems (HRIS, Payroll, Benefits).
"""

from typing import Dict, Any, List, Tuple

# Finch Scopes and Risk Catalog
FINCH_SCOPES = {
    "company:read": {
        "name": "Read Company Information",
        "description": "Read company legal entity name, EIN, primary address, and business structure.",
        "risk_weight": 5.0,
        "category": "ORGANIZATION",
        "tier": 1,
        "risk_implication": "Low risk; corporate metadata."
    },
    "directory:read": {
        "name": "Read Employee Directory",
        "description": "Access active employee list, department names, work emails, and manager relationships.",
        "risk_weight": 5.0,
        "category": "ORGANIZATION",
        "tier": 1,
        "risk_implication": "Low risk; standard work directory information."
    },
    "employment:read": {
        "name": "Read Employment Details",
        "description": "Access employment status (active/terminated), hire dates, job titles, and worker type (1099/W2).",
        "risk_weight": 10.0,
        "category": "EMPLOYMENT",
        "tier": 2,
        "risk_implication": "Moderate risk; reveals organizational restructuring and tenure."
    },
    "individual:read": {
        "name": "Read Personal PII",
        "description": "Access employee personal email, phone numbers, home physical address, gender, and date of birth.",
        "risk_weight": 18.0,
        "category": "PII",
        "tier": 3,
        "risk_implication": "HIGH RISK: Leaks personal addresses and phone numbers; privacy regulation liability (GDPR/CCPA)."
    },
    "benefits:read": {
        "name": "Read Benefit Enrollments",
        "description": "View employee medical, dental, vision, and 401(k) retirement deduction plans.",
        "risk_weight": 15.0,
        "category": "BENEFITS",
        "tier": 3,
        "risk_implication": "HIGH RISK: Exposes health plan participation and pre-tax deductions."
    },
    "payment:read": {
        "name": "Read Payment Runs",
        "description": "View aggregate company payroll run summaries, pay periods, and gross debit batches.",
        "risk_weight": 20.0,
        "category": "FINANCIAL",
        "tier": 4,
        "risk_implication": "HIGH RISK: Discloses corporate payroll outflow totals and banking debits."
    },
    "pay_statement:read": {
        "name": "Read Individual Pay Statements",
        "description": "Detailed view of individual compensation: wages, bonuses, hourly rates, taxes withheld, and bank account numbers.",
        "risk_weight": 25.0,
        "category": "FINANCIAL",
        "tier": 4,
        "risk_implication": "CRITICAL RISK: Exposes exact salaries of all employees and executives; insider threat / extortion risk."
    },
    "ssn:read": {
        "name": "Read Social Security Numbers",
        "description": "Unmasked access to employee Social Security Numbers and national tax IDs.",
        "risk_weight": 30.0,
        "category": "CRITICAL_PII",
        "tier": 4,
        "risk_implication": "CRITICAL RISK: Severe identity theft vector; breaches compliance standards (SOC2, HIPAA, State Privacy Laws)."
    },
    "benefits:write": {
        "name": "Modify Benefits & Deductions",
        "description": "Enroll, modify, or terminate employee health insurance and retirement elections.",
        "risk_weight": 25.0,
        "category": "MUTATION",
        "tier": 5,
        "risk_implication": "CRITICAL RISK: Can tamper with employee healthcare coverage and 401k contribution deductions."
    },
    "payment:write": {
        "name": "Initiate / Alter Payroll Payments",
        "description": "Initiate automated bonus payments, change direct deposit destinations, or submit payroll batches.",
        "risk_weight": 35.0,
        "category": "MUTATION",
        "tier": 5,
        "risk_implication": "CATASTROPHIC RISK: Unauthorized movement of company capital and direct deposit wire redirection."
    }
}

ENDPOINT_SCOPE_RULES: List[Tuple[str, str, str]] = [
    ("GET", "/employer/company", "company:read"),
    ("GET", "/employer/directory", "directory:read"),
    ("GET", "/employer/employment", "employment:read"),
    ("GET", "/employer/individual", "individual:read"),
    ("GET", "/employer/payment", "payment:read"),
    ("GET", "/employer/pay-statement", "pay_statement:read"),
    ("POST", "/employer/payment", "payment:write"),
    ("GET", "/employer/benefits", "benefits:read"),
    ("POST", "/employer/benefits", "benefits:write"),
]

def resolve_finch_scope(method: str, path: str) -> str:
    """Matches a Finch API endpoint and method to the required permission scope."""
    method_upper = method.upper()
    for rule_method, pattern, scope in ENDPOINT_SCOPE_RULES:
        if rule_method == method_upper and pattern == path:
            return scope
    
    # Heuristics
    if "payment" in path:
        return "payment:write" if method_upper == "POST" else "payment:read"
    elif "pay-statement" in path:
        return "pay_statement:read"
    elif "benefit" in path:
        return "benefits:write" if method_upper == "POST" else "benefits:read"
    elif "individual" in path:
        return "individual:read"
    elif "employment" in path:
        return "employment:read"
    elif "company" in path:
        return "company:read"
    return "directory:read"
