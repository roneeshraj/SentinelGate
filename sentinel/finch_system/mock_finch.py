"""
Mock Finch Unified Employment API Engine.
Simulates HRIS and Payroll endpoints with realistic multi-tiered data.
"""

from typing import Dict, Any, List, Tuple, Optional
from sentinel.finch_system.finch_permissions import resolve_finch_scope, FINCH_SCOPES

MOCK_COMPANY = {
    "id": "comp_9981249",
    "legal_name": "Nexus Dynamics Inc.",
    "ein": "12-3456789",
    "primary_email": "hr@nexusdynamics.io",
    "departments": ["Engineering", "Product", "Operations", "Finance", "Human Resources"],
    "headcount": 142
}

MOCK_EMPLOYEES = [
    {
        "id": "emp_001",
        "first_name": "Sarah",
        "last_name": "Connor",
        "work_email": "sarah.connor@nexusdynamics.io",
        "department": "Engineering",
        "title": "VP of Engineering",
        "employment_status": "active",
        "start_date": "2022-03-01",
        "phone": "+1-555-0199",
        "personal_email": "sconnor_private@gmail.com",
        "home_address": "404 Cyber Way, Austin, TX 78701",
        "ssn": "987-65-4412",
        "salary_usd": 260000,
        "hourly_rate": None,
        "direct_deposit_bank": "Chase Bank (Acct: ...9812)",
        "benefits": ["Premium PPO Healthcare", "Max 401(k) Match"]
    },
    {
        "id": "emp_002",
        "first_name": "John",
        "last_name": "Doe",
        "work_email": "john.doe@nexusdynamics.io",
        "department": "Engineering",
        "title": "Principal Security Architect",
        "employment_status": "active",
        "start_date": "2023-01-15",
        "phone": "+1-555-0143",
        "personal_email": "johndoe_real@fastmail.com",
        "home_address": "12 Ocean Drive, Austin, TX 78704",
        "ssn": "987-65-8821",
        "salary_usd": 195000,
        "hourly_rate": None,
        "direct_deposit_bank": "Wells Fargo (Acct: ...3341)",
        "benefits": ["Standard Health", "HSA", "401(k)"]
    },
    {
        "id": "emp_003",
        "first_name": "Alice",
        "last_name": "Walker",
        "work_email": "alice.walker@nexusdynamics.io",
        "department": "Operations",
        "title": "Senior DevOps Engineer",
        "employment_status": "active",
        "start_date": "2023-06-20",
        "phone": "+1-555-0177",
        "personal_email": "alice_w@outlook.com",
        "home_address": "88 Pine St, Round Rock, TX 78664",
        "ssn": "987-65-1109",
        "salary_usd": 170000,
        "hourly_rate": None,
        "direct_deposit_bank": "Bank of America (Acct: ...5502)",
        "benefits": ["Standard Health", "401(k)"]
    },
    {
        "id": "emp_004",
        "first_name": "Bob",
        "last_name": "Martin",
        "work_email": "bob.martin@nexusdynamics.io",
        "department": "Human Resources",
        "title": "HR Generalist",
        "employment_status": "active",
        "start_date": "2024-02-01",
        "phone": "+1-555-0112",
        "personal_email": "bmartin_tx@yahoo.com",
        "home_address": "301 Barton Creek, Austin, TX 78746",
        "ssn": "987-65-3344",
        "salary_usd": 110000,
        "hourly_rate": None,
        "direct_deposit_bank": "USAA (Acct: ...7729)",
        "benefits": ["Basic HMO Health"]
    }
]

class MockFinchEngine:
    """Handles simulated Finch API requests and verifies scopes."""

    @staticmethod
    def handle_request(
        method: str,
        path: str,
        token_scopes: List[str],
        mask_sensitive_pii: bool = False
    ) -> Tuple[int, Dict[str, Any], str, List[str]]:
        """
        Executes a mock Finch API request.
        Returns: (status_code, response_body, matched_scope, redacted_fields)
        """
        matched_scope = resolve_finch_scope(method, path)
        redacted_fields: List[str] = []

        # Scope Check
        if matched_scope not in token_scopes:
            return (
                403,
                {
                    "error": "FORBIDDEN",
                    "message": f"Unauthorized Finch scope. Action requires '{matched_scope}'.",
                    "required_scope": matched_scope,
                    "granted_scopes": token_scopes
                },
                matched_scope,
                []
            )

        method = method.upper()

        if path == "/employer/company":
            return 200, {"company": MOCK_COMPANY}, matched_scope, []

        elif path == "/employer/directory":
            # Directory returns public work profile
            directory = [
                {
                    "id": e["id"],
                    "first_name": e["first_name"],
                    "last_name": e["last_name"],
                    "work_email": e["work_email"],
                    "department": e["department"]
                }
                for e in MOCK_EMPLOYEES
            ]
            return 200, {"directory": directory, "count": len(directory)}, matched_scope, []

        elif path == "/employer/employment":
            employment_records = [
                {
                    "id": e["id"],
                    "first_name": e["first_name"],
                    "last_name": e["last_name"],
                    "title": e["title"],
                    "department": e["department"],
                    "employment_status": e["employment_status"],
                    "start_date": e["start_date"]
                }
                for e in MOCK_EMPLOYEES
            ]
            return 200, {"employment": employment_records}, matched_scope, []

        elif path == "/employer/individual":
            has_ssn_scope = ("ssn:read" in token_scopes) and not mask_sensitive_pii
            individuals = []
            for e in MOCK_EMPLOYEES:
                record = {
                    "id": e["id"],
                    "first_name": e["first_name"],
                    "last_name": e["last_name"],
                    "phone": e["phone"] if not mask_sensitive_pii else "[REDACTED_PHONE]",
                    "personal_email": e["personal_email"] if not mask_sensitive_pii else "[REDACTED_EMAIL]",
                    "home_address": e["home_address"] if not mask_sensitive_pii else "[REDACTED_ADDRESS]",
                    "ssn": e["ssn"] if has_ssn_scope else "[REDACTED_SSN]"
                }
                if not has_ssn_scope or mask_sensitive_pii:
                    redacted_fields.append("ssn")
                if mask_sensitive_pii:
                    redacted_fields.extend(["phone", "personal_email", "home_address"])
                individuals.append(record)
            return 200, {"individuals": individuals}, matched_scope, list(set(redacted_fields))

        elif path == "/employer/pay-statement":
            has_ssn_scope = ("ssn:read" in token_scopes) and not mask_sensitive_pii
            statements = []
            for e in MOCK_EMPLOYEES:
                record = {
                    "employee_id": e["id"],
                    "name": f"{e['first_name']} {e['last_name']}",
                    "annual_salary_usd": e["salary_usd"] if not mask_sensitive_pii else "[REDACTED_COMPENSATION]",
                    "pay_period": "2026-11-01 to 2026-11-15",
                    "gross_pay": round(e["salary_usd"] / 24, 2) if not mask_sensitive_pii else "[REDACTED]",
                    "net_pay": round((e["salary_usd"] / 24) * 0.72, 2) if not mask_sensitive_pii else "[REDACTED]",
                    "direct_deposit": e["direct_deposit_bank"] if not mask_sensitive_pii else "[REDACTED_BANK]",
                    "ssn": e["ssn"] if has_ssn_scope else "[REDACTED_SSN]"
                }
                if mask_sensitive_pii:
                    redacted_fields.extend(["annual_salary_usd", "gross_pay", "net_pay", "direct_deposit"])
                if not has_ssn_scope or mask_sensitive_pii:
                    redacted_fields.append("ssn")
                statements.append(record)
            return 200, {"pay_statements": statements}, matched_scope, list(set(redacted_fields))

        elif path == "/employer/payment" and method == "GET":
            return 200, {
                "payments": [
                    {"batch_id": "batch_20261115", "total_gross": 31041.67, "status": "settled", "currency": "USD"},
                    {"batch_id": "batch_20261031", "total_gross": 31041.67, "status": "settled", "currency": "USD"}
                ]
            }, matched_scope, []

        elif path == "/employer/payment" and method == "POST":
            return 201, {
                "status": "initiated",
                "payment_id": "pay_run_9941029",
                "message": "Off-cycle payroll transaction initiated successfully",
                "amount_usd": 15000.00
            }, matched_scope, []

        elif path == "/employer/benefits" and method == "GET":
            benefits = [{"employee_id": e["id"], "enrolled_plans": e["benefits"]} for e in MOCK_EMPLOYEES]
            return 200, {"benefits": benefits}, matched_scope, []

        elif path == "/employer/benefits" and method == "POST":
            return 200, {"status": "updated", "message": "Benefit election updated successfully"}, matched_scope, []

        return 200, {"status": "ok", "message": "Finch operation completed"}, matched_scope, []
