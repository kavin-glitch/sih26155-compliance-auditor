# AI-Driven Multi-Vendor Network Security Compliance Auditor
**SIH26155 — National Technical Research Organisation (NTRO)**

A vendor-agnostic compliance engine that ingests network device configuration
files (Cisco, Fortinet, Juniper — and any future vendor), normalizes them
into a common security model, evaluates them against CIS-aligned controls,
and — critically — **learns to understand brand-new/unrecognized vendor
syntax through a human-confirmed AI training loop**, with no backend code
changes required.

## What's actually implemented (not mocked)
- Real regex/pattern-based parsers for **Cisco IOS**, **Fortinet FortiOS**, and **Juniper Junos**
- A shared **normalized security schema** (14 fields) — different vendor syntax converges to the same model
- A **deterministic compliance engine** evaluating 14 CIS-aligned controls, each with severity, evidence, and vendor-specific remediation commands
- An **AI interpretation layer** (`ai/unknown_command_ai.py`) that scores unrecognized config lines against known security categories and suggests a likely meaning with a confidence score
- A **human-in-the-loop training UI**: admin confirms/overrides the AI's suggestion, and the mapping is persisted (`ai/mappings.json`) — proven in `test_run.py` to generalize to a **second, never-seen device from the same vendor**
- **PDF reporting** (per-device and organization-wide dashboard) via ReportLab
- **Bulk/organization-wide audit** mode

## Project structure
```
app.py                     # Streamlit UI (single audit, bulk audit, training, learned mappings)
test_run.py                # headless end-to-end test (no browser needed)
models/schema.py           # normalized schema + category actions
parsers/                   # vendor_detector.py, cisco_parser.py, fortinet_parser.py, juniper_parser.py, generic_parser.py
compliance/rules.py        # CIS-aligned rule definitions (roadmap: NIST/STIG/ISO as new rule sets, same fields)
compliance/engine.py       # deterministic pass/fail evaluation
ai/unknown_command_ai.py   # keyword/pattern-based "AI" suggestion engine
ai/mapping_store.py        # persisted learned mappings (JSON)
reporting/pdf_report.py    # PDF generation
sample_configs/            # sample Cisco/Juniper/Fortinet configs + a fictional "unknown vendor" pair for the live training demo
```

## Setup
```bash
pip install -r requirements.txt
```

## Run the app
```bash
streamlit run app.py
```
Then open the local URL Streamlit prints (usually http://localhost:8501).

## Run the automated test (proves the training loop actually works)
```bash
python test_run.py
```
This scripts the exact demo scenario: parses known vendors, generates PDFs,
then feeds an unrecognized vendor's config, trains the system on every
unknown line, re-parses the SAME file (0 unmatched lines), and then parses a
DIFFERENT device from the SAME vendor (also 0 unmatched lines) — proving the
learned mapping generalizes, not just memorizes one file.

## Live demo script (suggested)
1. Upload `sample_configs/cisco_sample.cfg` → show vendor detection, pass/fail findings, evidence, remediation, PDF export.
2. Switch to "Train Unknown Vendor" → upload `sample_configs/unknown_vendor_sample.cfg` (label: `edgecore`) → show several lines are unrecognized.
3. For 2–3 lines, show the AI's suggested category + confidence → click confirm.
4. Re-upload the same file → 0 unrecognized lines, findings appear.
5. Upload `sample_configs/unknown_vendor_sample_device2.cfg` (a **different device**, same vendor, never seen before) → show it is *already* fully recognized — no retraining needed. This is the moment that proves the "dynamic adaptation" requirement.

## Roadmap (architecture supports these, not yet implemented)
- NIST SP 800-53 / DISA STIG / ISO 27001 rule sets (same normalized fields — see `compliance/rules.py` comments)
- Additional vendor parsers (Palo Alto, Check Point, Arista, SONiC, cloud-native)
- Config drift detection between scans of the same device
- Confidence-weighted auto-approval threshold for high-confidence AI suggestions
