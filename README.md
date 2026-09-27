# Build Security

> **Smart India Hackathon 2026 · Problem Statement 26163**  
> **Security Assessment of the World Monitor application**

Build Security is an evidence-first security assessment workspace for an authorized Web/Mobile World Monitor test environment. It combines a safe assessment engine, a deliberately vulnerable local lab, two-identity authorization checks, and exportable reports in one operator-friendly interface.

## Why this project is different

Most student security projects stop at a list of scanner findings. Build Security is designed around the review workflow:

**Discover → Validate → Explain → Remediate → Re-test**

The dashboard deliberately separates machine-generated **signals** from confirmed vulnerabilities, shows the evidence behind every signal, and produces a report that can be used during a technical security review.

## Core capabilities

- Security headers: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking protection signals.
- Authentication and session hygiene: Secure, HttpOnly, SameSite cookie signals.
- API security: CORS wildcard and origin-reflection review on configured GET endpoints.
- Transport: HTTP/HTTPS and HSTS checks.
- Authorization: controlled two-identity differential testing using explicit GET endpoints and test credentials you own.
- Evidence console: findings, evidence, CWE, remediation and verification steps.
- Executive posture index: quick summary for demonstrations and review sessions. It is a project metric, not a standards-based risk score.
- Reports: standalone JSON and HTML reports.
- Local vulnerable lab: intentionally weak application used for safe PoC demonstrations.

## Product flow

```text
                      +---------------------------+
                      |  Build Security Console   |
                      |  Target + Scope + Consent  |
                      +-------------+-------------+
                                    |
                                    v
                      +---------------------------+
                      |      Assessment Engine     |
                      | headers | cookies | CORS  |
                      | transport | configured API |
                      +-------------+-------------+
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
       +-------------------+                +-------------------+
       | Authorization Lab |                | Evidence / Report |
       | 2 test identities |                | JSON + HTML       |
       +-------------------+                +-------------------+
```

## Safety model

Use only against systems where you have explicit authorization.

- GET-only automated checks
- No brute force
- No credential guessing
- No database writes
- No destructive exploitation
- No automatic ID enumeration
- Authorization testing requires explicit endpoints and two test identities
- Automated signals must be manually validated before being presented as confirmed vulnerabilities

## Local demo

The repository ships with an intentionally vulnerable local FastAPI service. It demonstrates weak headers, permissive CORS, insecure cookies and an IDOR-style report endpoint without touching a real third-party system.

### 1. Install

```bash
python -m venv .venv

# Windows
.venv\\Scripts\\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Start the demo lab

```bash
uvicorn lab.vulnerable_app:app --reload --port 8001
```

### 3. Start Build Security

```bash
uvicorn app.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000**.

The dashboard includes a **Load local demo lab** shortcut.

## CLI

```bash
python -m scanner.cli \
  --target http://127.0.0.1:8001 \
  --endpoint / \
  --endpoint /api/health \
  --endpoint /api/reports/1 \
  --endpoint /api/reports/2 \
  --output reports/lab-report
```

Authorized deployment example:

```bash
python -m scanner.cli \
  --target https://AUTHORIZED-TEST-HOST \
  --endpoint /api/health \
  --endpoint /api/reports/1 \
  --output reports/world-monitor
```

## API

- `GET /api/health` service health
- `GET /api/info` capability metadata
- `POST /api/assess` run an authorized assessment
- `GET /api/report/{filename}` retrieve the generated JSON/HTML report

Example request body:

```json
{
  "target": "http://127.0.0.1:8001",
  "endpoints": ["/", "/api/health", "/api/reports/1"],
  "headers": {},
  "authorization_check": false,
  "authorized": true
}
```

## SIH presentation angle

The strongest story for a demo is not "our scanner found X bugs". Show the workflow:

1. Start the local vulnerable lab.
2. Load it from the Build Security dashboard.
3. Run the assessment and show the posture index moving from an untouched baseline.
4. Click a finding and show the exact evidence and remediation path.
5. Open the HTML report and explain how the same evidence can become a security assessment deliverable.
6. Demonstrate the two-identity authorization check with controlled test data.
7. Explain how the same workflow maps to the authorized World Monitor staging environment.

## Tech stack

- Python 3.11+
- FastAPI
- Requests
- Pydantic
- HTML/CSS/JavaScript frontend
- JSON + HTML reporting

## Project structure

```text
Build-security/
├── app/
│   ├── main.py
│   └── static/
│       └── index.html
├── lab/
│   └── vulnerable_app.py
├── scanner/
│   ├── authz.py
│   ├── cli.py
│   ├── http_checks.py
│   ├── models.py
│   └── report.py
├── tests/
├── requirements.txt
├── Makefile
└── README.md
```

---

**Build Security · Team project for Smart India Hackathon 2026 · PS 26163**
