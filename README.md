# 🛡️ Vulnerability Intelligence Center (VIC)

VIC is a local, enterprise-style Streamlit dashboard that converts Qualys/Panaseer vulnerability exports into security-posture, investigation, remediation, and rule-based intelligence views.

## Features

- Upload a compatible CSV or use the bundled sample export.
- Filtered KPI cards and interactive Plotly visualisations.
- Searchable vulnerability explorer, CSV export, and asset drill-down.
- Transparent risk-priority scoring plus a 30-day remediation plan.
- Executive summaries and security Q&A generated only with Pandas, NumPy, and rules—no LLMs, APIs, or external services.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running locally

```powershell
streamlit run app.py
```

The sample data at `data/Qualys_Panaseer_Server_Vulnerabilities_1000Rows.csv` loads automatically. To use your own export, upload a CSV containing the expected VIC columns.

## Future roadmap

- SSO and role-based access
- Remediation workflow tracking and persistence
- Scheduled reports and evidence exports
- Further scanner-schema adapters
