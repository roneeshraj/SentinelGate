"""
Command-Line Interface (CLI) for SentinelGate.
Allows security engineers and CI/CD pipelines to audit, demonstrate, and remediate excessive API permissions.
"""

import sys
import argparse
import json
from sentinel.database import (
    init_db,
    get_all_credentials,
    get_credential_by_id,
    get_proxy_mode,
    set_proxy_mode,
    get_access_logs
)
from sentinel.analyzer.gap_analyzer import GapAnalyzer
from sentinel.analyzer.demonstrator import PermissionDemonstrator
from sentinel.remediation.policy_generator import PolicyGenerator
from sentinel.remediation.remediator import Remediator
from sentinel.web.server import run_server

def cmd_audit(args):
    init_db()
    if args.cred_id:
        audit = GapAnalyzer.audit_credential(args.cred_id)
        if not audit:
            print(f"[!] Credential '{args.cred_id}' not found.")
            sys.exit(1)
        _print_audit_summary(audit.to_dict())
    else:
        creds = get_all_credentials()
        print(f"\n{'='*80}")
        print(f" SENTINELGATE API AUDIT: THIRD-PARTY ACCESS SECURITY MATRIX")
        print(f"{'='*80}")
        print(f"{'CLIENT / CREDENTIAL':<30} {'SYSTEM':<10} {'EXCESS %':<10} {'RISK SCORE':<12} {'RISK LEVEL':<10}")
        print(f"{'-'*80}")
        for c in creds:
            audit = GapAnalyzer.audit_credential(c["id"])
            if audit:
                a_dict = audit.to_dict()
                print(f"{a_dict['client_name'][:28]:<30} {a_dict['system_type']:<10} {str(a_dict['excess_ratio'])+'%':<10} {a_dict['risk_score']:<12} {a_dict['risk_level']:<10}")
        print(f"{'='*80}\n")

def _print_audit_summary(a: dict):
    print(f"\n{'='*70}")
    print(f" AUDIT REPORT: {a['client_name']} ({a['system_type']})")
    print(f"{'='*70}")
    print(f" Credential ID:       {a['credential_id']}")
    print(f" Granted Scopes:      {', '.join(a['granted_scopes'])}")
    print(f" Active / Used:       {', '.join(a['observed_scopes']) or 'None'}")
    print(f" Unused / Excess:     {', '.join(a['unused_scopes']) or 'None'}")
    print(f" Excess Scope Ratio:  {a['excess_ratio']}%")
    print(f" Security Risk Score: {a['risk_score']} / 100")
    print(f" Risk Classification: {a['risk_level']}")
    print(f"\n Identified Threat Vectors:")
    for t in a["threat_vectors"]:
        print(f"  [-] {t}")
    print(f"{'='*70}\n")

def cmd_demonstrate(args):
    init_db()
    demo = PermissionDemonstrator.demonstrate_token_risk(args.cred_id)
    if "error" in demo:
        print(f"[!] Error: {demo['error']}")
        sys.exit(1)

    print(f"\n{'#'*80}")
    print(f" PROOF-OF-EXCESS DEMONSTRATION: {demo['client_name']} ({demo['system_type']})")
    print(f"{'#'*80}")
    print(f" Token Masked: {demo['token_masked']}")
    print(f" Granted Scopes: {', '.join(demo['granted_scopes'])}\n")

    legit = demo["legitimate_request"]
    print(f"[+] INTENDED BUSINESS OPERATION (Expected Normal Traffic):")
    print(f"    Endpoint:    {legit['method']} {legit['endpoint']}")
    print(f"    Scope Used:  {legit['scope_used']}")
    print(f"    Status:      HTTP {legit['status_code']}")
    print(f"    Description: {legit['description']}\n")

    exploit = demo["excessive_demonstration"]
    print(f"[!] EXCESSIVE CAPABILITY ABUSE (Security Threat Demonstrated):")
    print(f"    Endpoint:      {exploit['method']} {exploit['endpoint']}")
    print(f"    Scope Abused:  {exploit['scope_abused']}")
    print(f"    Status:        HTTP {exploit['status_code']} ({'ALLOWED' if exploit['exploit_allowed'] else 'BLOCKED'})")
    print(f"    Risk Analysis: {exploit['risk_analysis']}\n")
    print(f"    Demonstration Payload Extracted (Safe Sample):")
    print(json.dumps(exploit["sample_response"], indent=4))
    print(f"{'#'*80}\n")

def cmd_remediate(args):
    init_db()
    plan = PolicyGenerator.generate_plan(args.cred_id)
    if not plan:
        print(f"[!] Credential '{args.cred_id}' not found.")
        sys.exit(1)

    p_dict = plan.to_dict()
    print(f"\n{'-'*75}")
    print(f" LEAST-PRIVILEGE REMEDIATION PLAN: {p_dict['client_name']}")
    print(f"{'-'*75}")
    print(f" Plan ID:             {p_dict['id']}")
    print(f" Current Scopes:      {', '.join(p_dict['current_scopes'])}")
    print(f" Recommended Scopes:  {', '.join(p_dict['recommended_scopes'])}")
    print(f" Revoked Scopes:      {', '.join(p_dict['revoked_scopes'])}")
    print(f" Risk Reduction:      {p_dict['risk_score_before']} ➔ {p_dict['risk_score_after']} (-{p_dict['reduction_percentage']}%)")
    
    if args.apply:
        res = Remediator.apply_plan(plan.id)
        if res.get("success"):
            print(f"\n[✓] SUCCESS: {res['message']}")
        else:
            print(f"\n[!] Failed: {res.get('error')}")
    else:
        print("\n[*] Plan generated in PENDING state. Run with '--apply' to enforce immediately.")
    print(f"{'-'*75}\n")

def cmd_proxy_mode(args):
    init_db()
    if args.mode:
        set_proxy_mode(args.mode.upper())
        print(f"[✓] Proxy mode updated to: {args.mode.upper()}")
    else:
        mode = get_proxy_mode()
        print(f"[*] Current Gateway Enforcement Mode: {mode}")

def cmd_serve(args):
    run_server(port=args.port)

def main():
    parser = argparse.ArgumentParser(description="SentinelGate - Third-Party API Access Security Platform")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # audit
    p_audit = subparsers.add_parser("audit", help="Audit third-party integrations and identify excessive permissions")
    p_audit.add_argument("--cred", dest="cred_id", help="Audit a specific credential ID")

    # demonstrate
    p_demo = subparsers.add_parser("demonstrate", help="Run a live proof-of-excess demonstration")
    p_demo.add_argument("--cred", dest="cred_id", required=True, help="Credential ID to demonstrate")

    # remediate
    p_rem = subparsers.add_parser("remediate", help="Generate least-privilege remediation plan")
    p_rem.add_argument("--cred", dest="cred_id", required=True, help="Credential ID to remediate")
    p_rem.add_argument("--apply", action="store_true", help="Automatically apply remediation")

    # mode
    p_mode = subparsers.add_parser("mode", help="View or update gateway enforcement mode")
    p_mode.add_argument("mode", nargs="?", choices=["MONITOR", "ENFORCE", "REDACT"], help="Enforcement mode")

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch the Web UI Dashboard and Gateway API")
    p_serve.add_argument("--port", type=int, default=8888, help="Port to listen on (default: 8888)")

    args = parser.parse_args()

    if args.command == "audit":
        cmd_audit(args)
    elif args.command == "demonstrate":
        cmd_demonstrate(args)
    elif args.command == "remediate":
        cmd_remediate(args)
    elif args.command == "mode":
        cmd_proxy_mode(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
