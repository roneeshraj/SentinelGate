"""
Web Server and REST API Gateway for SentinelGate.
Built with Python 3.14 standard library (ThreadingHTTPServer) with zero external dependencies.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional

from sentinel.config import SERVER_HOST, SERVER_PORT, STATIC_DIR, MODE_MONITOR, MODE_ENFORCE, MODE_REDACT
from sentinel.database import (
    init_db,
    get_all_clients,
    get_all_credentials,
    get_credential_by_id,
    get_access_logs,
    get_proxy_mode,
    set_proxy_mode,
    get_all_remediation_plans,
    record_access_log
)
from sentinel.models import SystemType
from sentinel.analyzer.gap_analyzer import GapAnalyzer
from sentinel.analyzer.blast_radius import BlastRadiusModeler
from sentinel.analyzer.demonstrator import PermissionDemonstrator
from sentinel.remediation.policy_generator import PolicyGenerator
from sentinel.remediation.remediator import Remediator
from sentinel.remediation.proxy_gateway import ProxyGateway

class SentinelApiHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for SentinelGate REST API and Web Dashboard."""

    def log_message(self, format, *args):
        # Suppress noisy stderr request logs
        pass

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Static assets
        if path == "/" or path == "/index.html":
            self._serve_static_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        elif path.startswith("/static/"):
            rel_path = path.replace("/static/", "")
            file_path = STATIC_DIR / rel_path
            mime = "text/css" if path.endswith(".css") else ("application/javascript" if path.endswith(".js") else "text/plain")
            self._serve_static_file(file_path, mime)
            return

        # REST API Routes
        try:
            if path == "/api/overview":
                self._handle_overview()
            elif path == "/api/clients":
                clients = get_all_clients()
                self._send_json(200, {"clients": clients})
            elif path == "/api/credentials":
                creds = get_all_credentials()
                self._send_json(200, {"credentials": creds})
            elif path == "/api/audits":
                self._handle_all_audits()
            elif path.startswith("/api/audit/"):
                cred_id = path.replace("/api/audit/", "")
                self._handle_single_audit(cred_id)
            elif path.startswith("/api/demonstrate/"):
                cred_id = path.replace("/api/demonstrate/", "")
                demo = PermissionDemonstrator.demonstrate_token_risk(cred_id)
                self._send_json(200, demo)
            elif path == "/api/remediation/plans":
                plans = get_all_remediation_plans()
                self._send_json(200, {"plans": plans})
            elif path == "/api/proxy/mode":
                mode = get_proxy_mode()
                self._send_json(200, {"mode": mode})
            elif path == "/api/logs":
                cred_id = query_params.get("credential_id", [None])[0]
                limit = int(query_params.get("limit", [50])[0])
                logs = get_access_logs(cred_id, limit)
                self._send_json(200, {"logs": logs})
            else:
                self._send_json(404, {"error": "Endpoint not found"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Read JSON body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_length > 0:
            raw_data = self.rfile.read(content_length)
            try:
                body = json.loads(raw_data.decode("utf-8"))
            except Exception:
                body = {}

        try:
            if path.startswith("/api/remediation/plan/"):
                cred_id = path.replace("/api/remediation/plan/", "")
                plan = PolicyGenerator.generate_plan(cred_id)
                if plan:
                    self._send_json(200, plan.to_dict())
                else:
                    self._send_json(404, {"error": f"Credential {cred_id} not found"})

            elif path.startswith("/api/remediation/apply/"):
                plan_id = path.replace("/api/remediation/apply/", "")
                res = Remediator.apply_plan(plan_id)
                self._send_json(200 if res.get("success") else 400, res)

            elif path.startswith("/api/remediation/rollback/"):
                plan_id = path.replace("/api/remediation/rollback/", "")
                res = Remediator.rollback_plan(plan_id)
                self._send_json(200 if res.get("success") else 400, res)

            elif path == "/api/proxy/mode":
                new_mode = body.get("mode", MODE_MONITOR)
                if new_mode in (MODE_MONITOR, MODE_ENFORCE, MODE_REDACT):
                    set_proxy_mode(new_mode)
                    self._send_json(200, {"mode": new_mode, "message": f"Proxy mode switched to {new_mode}"})
                else:
                    self._send_json(400, {"error": f"Invalid mode '{new_mode}'"})

            elif path == "/api/simulate/traffic":
                self._handle_simulate_traffic(body)

            elif path.startswith("/proxy/finch"):
                target_path = body.get("path", "/employer/directory")
                token = body.get("token") or self._extract_token()
                method = body.get("method", "GET")
                code, resp = ProxyGateway.process_request(SystemType.FINCH, token, method, target_path)
                self._send_json(code, resp)

            elif path.startswith("/proxy/harbor"):
                target_path = body.get("path", "/api/v2.0/projects")
                token = body.get("token") or self._extract_token()
                method = body.get("method", "GET")
                code, resp = ProxyGateway.process_request(SystemType.HARBOR, token, method, target_path)
                self._send_json(code, resp)

            else:
                self._send_json(404, {"error": "Endpoint not found"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _extract_token(self) -> str:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header.replace("Bearer ", "").strip()
        return ""

    def _serve_static_file(self, file_path: Path, content_type: str):
        if not file_path.exists():
            self._send_json(404, {"error": "File not found"})
            return
        with open(file_path, "rb") as f:
            content = f.read()
        self._set_headers(200, content_type)
        self.wfile.write(content)

    def _send_json(self, status: int, data: Dict[str, Any]):
        self._set_headers(status, "application/json")
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _handle_overview(self):
        creds = get_all_credentials()
        all_audits = []
        for c in creds:
            a = GapAnalyzer.audit_credential(c["id"])
            if a:
                all_audits.append(a)
        audits = all_audits
        
        total_integrations = len(creds)
        overprivileged_count = sum(1 for a in audits if a.excess_ratio > 0)
        critical_count = sum(1 for a in audits if a.risk_level.value == "CRITICAL")
        high_count = sum(1 for a in audits if a.risk_level.value == "HIGH")
        avg_excess = (sum(a.excess_ratio for a in audits) / len(audits)) if audits else 0.0

        logs = get_access_logs(limit=200)
        blocked_count = sum(1 for log in logs if log["blocked"])
        mode = get_proxy_mode()

        self._send_json(200, {
            "total_integrations": total_integrations,
            "overprivileged_count": overprivileged_count,
            "critical_risk_count": critical_count,
            "high_risk_count": high_count,
            "average_excess_ratio": round(avg_excess, 1),
            "blocked_requests_count": blocked_count,
            "current_proxy_mode": mode
        })

    def _handle_all_audits(self):
        creds = get_all_credentials()
        audits = []
        for c in creds:
            audit = GapAnalyzer.audit_credential(c["id"])
            if audit:
                audits.append(audit.to_dict())
        self._send_json(200, {"audits": audits})

    def _handle_single_audit(self, cred_id: str):
        audit = GapAnalyzer.audit_credential(cred_id)
        if not audit:
            self._send_json(404, {"error": f"Credential {cred_id} not found"})
            return
        nodes, edges = BlastRadiusModeler.generate_graph(audit)
        audit.blast_radius_nodes = nodes
        audit.blast_radius_edges = edges
        self._send_json(200, audit.to_dict())

    def _handle_simulate_traffic(self, body: Dict[str, Any]):
        """Simulates incoming third-party API traffic bursts to show live monitoring and gateway enforcement."""
        creds = get_all_credentials()
        generated = 0
        
        for c in creds:
            # Simulate a normal and an out-of-baseline call
            system = SystemType(c["system_type"])
            token = c["token_value"]
            if system == SystemType.FINCH:
                # Normal
                ProxyGateway.process_request(system, token, "GET", "/employer/directory")
                # Rogue test
                ProxyGateway.process_request(system, token, "GET", "/employer/pay-statement")
            else:
                # Normal
                ProxyGateway.process_request(system, token, "GET", "/api/v2.0/projects/prod-apps/repositories/frontend/artifacts")
                # Rogue test
                ProxyGateway.process_request(system, token, "DELETE", "/api/v2.0/projects/prod-apps/repositories/frontend")
            generated += 2

        self._send_json(200, {"success": True, "generated_events": generated, "message": "Simulation traffic injected successfully."})

def run_server(port: int = SERVER_PORT):
    init_db()
    server_address = (SERVER_HOST, port)
    httpd = ThreadingHTTPServer(server_address, SentinelApiHandler)
    print(f"[*] SentinelGate Server running at http://{SERVER_HOST}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
