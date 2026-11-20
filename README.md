# SentinelGate: Third-Party API Access Security Platform
### Identifying, Demonstrating, and Enforcing Least Privilege Across Harbor & Finch Systems

SentinelGate is an enterprise-grade security platform engineered to detect, demonstrate, and remediate excessive permissions granted to third-party integrations across **Harbor** (Container & Artifact Supply Chain Registry) and **Finch** (Unified Employment, HRIS & Payroll API) environments.

---

## 1. Problem Statement & Challenge Analysis

In modern distributed ecosystems, third-party applications, automated bots, and partner integrations frequently operate with over-privileged API credentials:

1. **The Over-Privilege Gap (Granted vs. Observed Scopes)**:
   - When third-party apps integrate with enterprise platforms, developers often request broad permissions (e.g., `system:admin` or wildcard scopes like `company:*`, `pay_statement:read`, `payment:write`) during onboarding.
   - In production runtime, integrations only invoke a narrow fraction of those capabilities (e.g., merely reading an employee directory or checking an image digest).
   - This delta represents dormant, high-risk access that violates the **Principle of Least Privilege (PoLP)**.

2. **The Harbor Risk Plane (Artifact Supply Chain)**:
   - **Harbor** manages mission-critical container images and Helm charts.
   - Over-privileged robot accounts (e.g. CI/CD deployers or audit scanners) possessing `system:admin`, `repository:push`, `repository:delete`, or `webhook:manage` can be exploited to inject backdoored container layers, sabotage production repositories, or reroute build notifications to external command-and-control (C2) servers.

3. **The Finch Risk Plane (Workforce Identity, PII & Payroll)**:
   - **Finch** provides unified access to HRIS and payroll data (Workday, ADP, Gusto, BambooHR).
   - Non-critical apps (such as a Slack birthday bot or org-chart visualizer) granted access to `ssn:read`, `pay_statement:read`, or `payment:write` expose entire workforces to identity theft, executive salary leaks, and unauthorized cash disbursement risks.

4. **The Core Defense Need**:
   - Security teams need software to:
     - **Identify**: Automatically compute the permission divergence between granted scopes and actual runtime traffic.
     - **Demonstrate**: Provide non-destructive, verifiable proof-of-excess showing exact blast radius and exploitability vectors.
     - **Remediate**: Automatically synthesize down-scoped least-privilege configurations, enforce gateway guardrails, and provide one-click remediation with instant rollback.

---

## 2. Platform Architecture

```
                                    +----------------------------------------+
                                    |         Third-Party Consumers          |
                                    | (Slack Bot, ArgoCD, Expensify, Sonar)  |
                                    +----------------------------------------+
                                                        |
                                                        v
+----------------------------------------------------------------------------------------------------+
|                                    SENTINELGATE SECURITY PLATFORM                                  |
|                                                                                                    |
|   +------------------------------------+              +----------------------------------------+   |
|   |         Web Dashboard UI           |              |            CLI Automation              |   |
|   | (Audits, Demo Studio, Blast Radius)|              | (CI/CD Gates, Headless Security Audits)|   |
|   +------------------------------------+              +----------------------------------------+   |
|                     |                                                     |                        |
|                     +--------------------------+--------------------------+                        |
|                                                |                                                   |
|                                                v                                                   |
|                         +-----------------------------------------------+                          |
|                         |          REST API & Telemetry Engine          |                          |
|                         +-----------------------------------------------+                          |
|                                                |                                                   |
|            +-----------------------------------+-----------------------------------+               |
|            |                                   |                                   |               |
|            v                                   v                                   v               |
|   +-------------------+              +-------------------+               +-------------------+     |
|   |   Gap Analyzer    |              |   Demonstrator    |               | Policy Synthesizer|     |
|   | (Excess Ratio,    |              | (Proof-of-Excess, |               | (Least-Privilege  |     |
|   |  Risk Scoring)    |              |  Blast Radius)    |               |  Specs & Rego)    |     |
|   +-------------------+              +-------------------+               +-------------------+     |
|            |                                   |                                   |               |
|            +-----------------------------------+-----------------------------------+               |
|                                                |                                                   |
|                                                v                                                   |
|                         +-----------------------------------------------+                          |
|                         |    Active Least-Privilege Reverse Proxy       |                          |
|                         |   Modes: [ MONITOR | ENFORCE | REDACT ]       |                          |
|                         +-----------------------------------------------+                          |
+------------------------------------------------|---------------------------------------------------+
                                                 |
                         +-----------------------+-----------------------+
                         |                                               |
                         v                                               v
       +-----------------------------------+           +-----------------------------------+
       |           Harbor System           |           |           Finch System            |
       |  (Projects, Repos, Artifacts,     |           |  (Directory, Employment, PII,     |
       |   Robot Accounts, Webhooks)       |           |   Payroll, Payment Runs)          |
       +-----------------------------------+           +-----------------------------------+
```

---

## 3. Key Capabilities & Modules

### 🔍 1. Permission Gap & Risk Scoring Engine (`sentinel/analyzer/gap_analyzer.py`)
- Analyzes granted permissions vs observed runtime access logs.
- Calculates **Excess Privilege Ratio**:
  $$\text{Excess Ratio} = \frac{|\text{Unused Scopes}|}{|\text{Granted Scopes}|} \times 100\%$$
- Calculates multi-attribute **Security Risk Score** (0–100) weighting scope sensitivity:
  - Finch: `payment:write` (35 pts), `ssn:read` (30 pts), `pay_statement:read` (25 pts).
  - Harbor: `system:admin` (40 pts), `webhook:manage` (30 pts), `repository:delete` (25 pts).
- Categorizes risk: `CRITICAL` ($\ge 75$), `HIGH` ($\ge 50$), `MEDIUM` ($\ge 25$), `LOW` ($< 25$).

### 🔬 2. Proof-of-Excess Demonstrator (`sentinel/analyzer/demonstrator.py`)
- Runs side-by-side verification:
  - **Legitimate Request**: Shows normal expected functionality (e.g., Slack Bot reading `/employer/directory`).
  - **Excessive Capability Abuse**: Shows what the token can do under its current permissions (e.g., querying `/employer/pay-statement` to extract VP salaries and SSNs, or executing registry superuser commands).

### 🌐 3. Attack Surface & Blast Radius Visualizer (`sentinel/analyzer/blast_radius.py`)
- Models relationships as an interactive node-link graph:
  $$\text{Client Token} \longrightarrow \text{Scopes (Active vs Excess)} \longrightarrow \text{Exposed Assets} \longrightarrow \text{Threat Impact}$$
- Identifies critical assets: SSNs, Executive Salaries, Direct Deposit Accounts, Container Repositories, and Webhook Pipelines.

### 🛡️ 4. Automated Least-Privilege Remediation (`sentinel/remediation/`)
- **Automated Policy Synthesizer**: Generates exact, down-scoped configurations:
  - Harbor: CNCF Harbor Robot Account JSON specification restricted to exact projects and actions.
  - Finch: Minimal OAuth2 Scope configuration strings.
  - Open Policy Agent (OPA): Rego guardrail policies for API gateway enforcement.
- **One-Click Remediation**: Applies down-scoped permissions directly with rollback support.

### ⚡ 5. Inline API Gateway Enforcement (`sentinel/remediation/proxy_gateway.py`)
- Three operation modes:
  - `MONITOR`: Transparent logging of baseline vs out-of-baseline requests.
  - `ENFORCE`: Rejects requests outside the least-privilege baseline with HTTP 403 `EXCESSIVE_PERMISSION_BLOCKED`.
  - `REDACT`: Transparently strips sensitive PII fields (`ssn`, `direct_deposit`, `annual_salary_usd`) from response payloads.

---

## 4. Getting Started

### Prerequisites
- Python 3.10+ (Tested on Python 3.14.0).
- Zero external package dependencies needed! Uses standard Python library (`http.server`, `sqlite3`, `json`, `dataclasses`, `unittest`).

### Running the Web Dashboard & Gateway
Double-click `start_sentinel.bat` or run:
```powershell
python run_server.py
```
Open your browser at: **[http://127.0.0.1:8888/](http://127.0.0.1:8888/)**

### Running the CLI
Use `sentinel_cli.bat` or `python -m sentinel.cli`:

1. **Audit All Integrations**:
   ```powershell
   python -m sentinel.cli audit
   ```

2. **Audit a Specific Client**:
   ```powershell
   python -m sentinel.cli audit --cred cred_finch_slack_001
   ```

3. **Demonstrate Proof-of-Excess**:
   ```powershell
   python -m sentinel.cli demonstrate --cred cred_finch_slack_001
   ```

4. **Generate and Apply Least-Privilege Remediation**:
   ```powershell
   python -m sentinel.cli remediate --cred cred_harbor_argo_001 --apply
   ```

5. **Toggle Gateway Mode**:
   ```powershell
   python -m sentinel.cli mode ENFORCE
   ```

### Running the Test Suite
Execute the 17 unit and integration tests:
```powershell
python run_tests.py
```

---

## 5. Seed Integrations Included in the Demo Environment

| Client Name | System | Granted Scopes | Operational Usage | Risk & Threat Vector |
| :--- | :--- | :--- | :--- | :--- |
| **Slack Org & Birthday Bot** | Finch | `company:read`, `directory:read`, `individual:read`, `ssn:read`, `pay_statement:read`, `payment:read` | `directory:read`, `company:read` | **CRITICAL (93.0)**: Unnecessary access to employee SSNs & executive payroll ledgers. |
| **ExpensifyPro Travel & Spend** | Finch | `company:read`, `directory:read`, `employment:read`, `payment:read`, `payment:write`, `benefits:write` | `directory:read`, `employment:read` | **CRITICAL (85.0)**: Dormant `payment:write` permission allows unauthorized cash disbursements. |
| **BenefitFlo Enrollment Sync** | Finch | `directory:read`, `individual:read`, `benefits:read`, `benefits:write`, `ssn:read` | `directory:read`, `benefits:read`, `benefits:write` | **MEDIUM (48.0)**: Holds `ssn:read` scope beyond basic benefits configuration needs. |
| **ArgoCD Cluster Deployer** | Harbor | `repository:pull`, `repository:push`, `repository:delete`, `webhook:manage`, `project:admin`, `system:admin` | `repository:pull` | **CRITICAL (100.0)**: System admin superuser access allows full registry takeover & container sabotage. |
| **SonarQube Container Inspector** | Harbor | `repository:pull`, `artifact:read`, `repository:delete`, `scanner:configure` | `repository:pull`, `artifact:read` | **HIGH (50.0)**: Permission to delete production repositories and alter scanner policies. |
| **Prometheus Registry Exporter** | Harbor | `artifact:read`, `project:admin` | `artifact:read` | **MEDIUM (25.0)**: Holds `project:admin` privileges solely to read metric counts. |

---

## 6. Verification & Test Results

```
Ran 17 tests in 0.539s
OK (All unit, integration, and gateway tests passing)
```
- Harbor scope resolution, authorization & robot account generation: Verified.
- Finch scope resolution, PII masking & OAuth specification: Verified.
- Gap Analyzer & Risk Scoring formula: Verified.
- Proof-of-Excess Demonstrator & Blast Radius graph construction: Verified.
- Proxy Gateway under `MONITOR`, `ENFORCE`, and `REDACT` modes: Verified.
- Automated Least-Privilege Remediation & Rollback: Verified.
