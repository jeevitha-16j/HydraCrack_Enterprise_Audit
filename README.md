# HydraCrack Enterprise Security Audit Platform v3.0

HydraCrack is an **authorized, local password-security auditing and risk-assessment platform** for college laboratories, security education and controlled assessments.

## v3 capabilities
- Controlled dictionary/brute-force lab engine retained from v2
- MD5/SHA-1/SHA-256/SHA-512 fingerprint and policy analysis
- Password-KDF policy guidance for Argon2id, scrypt and bcrypt
- Risk scoring and findings
- SQLite audit history
- Local dashboard with risk distribution and audit history
- Local REST API: `/api/audits`, `/api/siem`, `/api/login`
- Demo RBAC authentication and API-token issuance
- JSON/CSV reports
- Professional PDF audit reports
- JSONL and CEF-like SIEM exports
- Automated unit tests
- Responsible-use and authorization controls

## Run
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
.\run_enterprise_demo.bat
.\run_enterprise_dashboard.bat
```
Dashboard: `http://127.0.0.1:8765`

Demo login is shown in the dashboard terminal. Change it before any shared deployment.

## Architecture
`Controlled lab test -> Audit core -> Risk engine -> SQLite history -> Dashboard/API -> PDF/CSV/JSON/SIEM exports`

## Security boundary
This release intentionally does **not** implement remote credential collection, credential stuffing, persistence, stealth, or unauthorized access. Use only synthetic or explicitly authorized data.
