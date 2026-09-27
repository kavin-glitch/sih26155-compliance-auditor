<div align="center">

# Multi-Vendor Network Security Compliance Auditor

### Vendor-agnostic compliance auditing with adaptive syntax learning

**SIH 2025 · Problem Statement ID 26155 · National Technical Research Organisation**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/tests-passing-2ea44f?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-prototype-orange?style=flat-square)]()
[![Offline](https://img.shields.io/badge/runs-100%25%20offline-blue?style=flat-square)]()

</div>

---

## The Problem

Enterprise networks run on hardware from a dozen vendors. A Cisco router, a Fortinet firewall, and a Juniper switch all need to meet the same CIS, NIST, and STIG baselines — but the same security intent is written differently on each.

```text
Cisco     →  ip ssh version 2
Fortinet  →  set admin-ssh-v1 disable
Juniper   →  set system services ssh protocol-version v2
```

Today, organizations either audit every device by hand or buy a vendor-locked tool that becomes obsolete the moment a new platform enters the network. Neither scales.

---

## What This Is

A compliance auditor that:

- Normalizes **any vendor's** configuration into a single security model
- Evaluates it against **multiple frameworks** with deterministic rules
- **Learns** to interpret vendor syntax it has never seen before

No code redeploys. No vendor lock-in. No black-box verdicts.

---

## The Core Principle

> ### AI interprets unfamiliar syntax. Rules make every compliance decision.

That separation is why the verdicts are defensible. When a control fails, we can point to:

1. The exact config line as evidence
2. The normalized value derived from it
3. The rule that evaluated it
4. The standard it maps to

Nothing in the compliance path is opaque. The AI sits entirely outside the decision loop.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│   Config file (Cisco / Fortinet / Juniper / unknown)         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Vendor detection │
                  └───────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │  Vendor parser  ←→  Learned mappings (JSON) │
              └───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────┐
        │  Universal Security Model                  │
        │  14 normalized fields, each source-tagged  │
        └───────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────┐
        │  Deterministic compliance engine           │
        │  CIS + NIST rule lists                     │
        └───────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────┐
        │  Findings                                  │
        │  status · severity · evidence · detected · │
        │  expected · attack path · remediation      │
        └───────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────┐
        │  PDF reports (per-device + fleet)          │
        └───────────────────────────────────────────┘
```

When the parser hits syntax it does not recognize:

```text
Unknown command
      │
      ▼
AI suggests category + confidence
      │
      ▼
Human confirms
      │
      ▼
Mapping persisted to JSON
      │
      ▼
Recognized automatically on next upload
```

---

## The Adaptive Learning Loop

Other tools fail silently on unfamiliar syntax. This one turns it into a one-time onboarding step.

| # | Action | Result |
|:-:|:-------|:-------|
| 1 | Parse Cisco, Fortinet, Juniper samples | Baseline compliance reports |
| 2 | Upload fictional "EdgeCore" config | ~12 unrecognized lines |
| 3 | Confirm AI-suggested mappings | Mappings persisted to JSON |
| 4 | Re-parse **same** file | **0 unrecognized lines** |
| 5 | Parse a **different, never-seen** device from same vendor | **0 unrecognized lines** |

**Step 5 is what matters.** It proves the system learned the vendor's command shape — not just memorized the file it was trained on.

---

## Findings — What Every Control Produces

Every failing control carries six pieces of information, in both the UI and the PDF:

| # | Field | Example |
|:-:|:------|:--------|
| 1 | **Status + Severity** | `FAIL` · High |
| 2 | **Evidence** (exact config line) | `transport input telnet ssh` |
| 3 | **Detected value** | Telnet enabled |
| 4 | **Expected value** | Telnet must be disabled |
| 5 | **Why it matters + potential attack path** | Credential sniffing → session hijack → device control |
| 6 | **Vendor-specific remediation + meaning** | `line vty 0 4 / transport input ssh` — removes Telnet from vty lines, forcing SSH |

That is the standard every finding should be held to. It is also the standard most tools fail.

---

## Coverage

### Vendors

| Vendor | Status | Sample |
|:-------|:------:|:-------|
| Cisco IOS | ✅ Real regex parser | `sample_configs/cisco_sample.cfg` |
| Fortinet FortiOS | ✅ Real regex parser | `sample_configs/fortinet_sample.cfg` |
| Juniper Junos | ✅ Real regex parser | `sample_configs/juniper_sample.cfg` |
| Any unknown vendor | ✅ Generic parser + AI training | `sample_configs/unknown_vendor_sample.cfg` |

### Frameworks

| Framework | Controls | Status |
|:----------|:--------:|:-------|
| CIS Network Device Hardening | 14 | ✅ Implemented |
| NIST SP 800-53 | 14 | ✅ Implemented |
| DISA STIG | — | Roadmap |
| ISO 27001 | — | Roadmap |

---

## Setup

```bash
git clone https://github.com/kavin-glitch/sih26155-compliance-auditor.git
cd sih26155-compliance-auditor

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Mac / Linux

pip install -r requirements.txt
streamlit run app.py
```

Open **http://localhost:8501**.

**Verify the full pipeline headlessly:**

```bash
python test_run.py
```

Terminal ends with:

```text
✅ ALL CHECKS PASSED — parsers, normalization, compliance engine,
   AI training loop, and PDF reporting all work end-to-end.
```

---

## Try It in Three Minutes

### 1 · Fleet Audit

Mode → **Audit** → drop in all three vendor configs at once.

You get a fleet table (vendor · score · high-severity count · unrecognized lines) plus per-device detail. Click any failing control to drill into the evidence chain.

### 2 · The Demo

Mode → **Train Unknown Vendor** → label `edgecore` → upload `unknown_vendor_sample.cfg`.

Confirm the AI-suggested mappings, click **Re-run Audit**, then upload `unknown_vendor_sample_device2.cfg`. A device the system has never seen is recognized instantly, because it learned the vendor — not the file.

### 3 · The Knowledge Base

Mode → **Learned Mappings** → every confirmed mapping, editable in place. Command pattern, category, normalized field, example, source. This is the persistent memory that makes the whole thing work.

---

## Repository Layout

```text
app.py                         Streamlit dashboard

models/
    schema.py                  14 normalized fields + training categories

parsers/
    vendor_detector.py         Vendor fingerprinting
    cisco_parser.py
    fortinet_parser.py
    juniper_parser.py
    generic_parser.py          Unknown vendors

compliance/
    rules.py                   CIS + NIST rule definitions
    engine.py                  Deterministic PASS/FAIL evaluation
    risk_context.py            Attack-path + impact text per control

ai/
    unknown_command_ai.py      Category suggestion engine
    mapping_store.py           Persistence layer
    mappings.json              Learned mappings (starts empty)

reporting/
    pdf_report.py              ReportLab PDF generation

sample_configs/                Cisco · Fortinet · Juniper · 2 unknown-vendor
outputs/                       Generated reports
test_run.py                    End-to-end verification
```

---

## How the Normalization Works

Every parser — regardless of vendor — outputs the same dictionary:

```python
{
    "telnet_enabled":               False,
    "ssh_version":                  2,
    "http_mgmt_enabled":            False,
    "https_mgmt_enabled":           True,
    "password_encryption":          True,
    "min_password_length":          10,
    "banner_configured":            True,
    "exec_timeout_minutes":         10,
    "logging_enabled":              True,
    "ntp_configured":               True,
    "aaa_configured":               True,
    "vty_acl_applied":              True,
    "weak_snmp_community_detected": False,
    "login_lockout_configured":     True,
}
```

The compliance rules only look at this dictionary. They do not know whether the config came from Cisco, Fortinet, or Juniper. **This is the entire vendor-agnostic story, in one file.** Adding a new vendor means writing one parser — or training the system through the UI. Nothing else in the codebase changes.

---

## Built With

| Layer | Stack |
|:------|:------|
| Core | Python 3.12 |
| Dashboard | Streamlit |
| Reporting | ReportLab |
| AI layer | Keyword + pattern scoring — fully offline, no external APIs |
| Persistence | JSON file store |

The entire system runs offline. Nothing phones home.

---

## Roadmap

| Feature | Why It's Easy to Add |
|:--------|:---------------------|
| DISA STIG + ISO 27001 rule sets | Same 14 normalized fields — just new rule lists |
| Palo Alto, Check Point, Arista, SONiC parsers | One file per vendor, same parser contract |
| Config drift detection | Diff two normalized models from the same device |
| Continuous monitoring + trend dashboard | Scheduled re-runs against the same rules |
| Live device collection | Netmiko / NAPALM integration on the input side |
| SIEM/SOC integration | Export findings as structured JSON |

None of these require changes to the core engine. That is the point of the architecture.

---

## Why This Is Different

Most compliance checkers are a fixed list of vendors and a fixed list of commands. The moment they see something new, they fail — and the operator gets no signal that the tool is stale.

This one does not. When the parser hits syntax it does not recognize, it flags it, gets a human to confirm what it means, and remembers. That is the difference between a script and a platform.

And because AI only *interprets* syntax while deterministic rules make every verdict, the compliance decisions are auditable. That is the standard security tooling should be held to.

---

<div align="center">

### AI interprets. Rules decide. Evidence proves.

**Kavin Krishna** · [@kavin-glitch](https://github.com/kavin-glitch)

Built for **Smart India Hackathon 2025**, Problem Statement **26155** — National Technical Research Organisation.

</div>
