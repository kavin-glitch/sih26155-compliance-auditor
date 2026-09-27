from compliance.rules import FRAMEWORKS
from compliance.risk_context import get_risk

GENERIC_REMEDIATION = "Manually review and harden this setting per the selected framework's guidance."


def _check(value, expected):
    if value is None:
        return "FAIL"
    if isinstance(expected, tuple):
        op, target = expected
        try:
            if op == ">=":
                return "PASS" if value >= target else "FAIL"
            if op == "<=":
                return "PASS" if value <= target else "FAIL"
        except TypeError:
            return "FAIL"
    return "PASS" if value == expected else "FAIL"


def _expected_text(expected):
    if isinstance(expected, tuple):
        op, target = expected
        return f"{op} {target}"
    if expected is True:
        return "Enabled / configured"
    if expected is False:
        return "Disabled / not present"
    return str(expected)


def _detected_text(value):
    if value is None:
        return "Not configured / not detected in this configuration."
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    return str(value)


def _evidence_line(evidence_value, field):
    if evidence_value is None:
        return f"No {field.replace('_', ' ')} configuration detected."
    return evidence_value


def _source_label(evidence_value):
    if evidence_value is None:
        return "not present in config"
    if "(platform default" in evidence_value or "(system default" in evidence_value:
        return "platform default"
    if "(learned mapping" in evidence_value or "(confirmed mapping" in evidence_value:
        return "learned mapping (human-confirmed)"
    return "config line"


def evaluate(normalized, evidence, vendor, framework="CIS"):
    rules = FRAMEWORKS.get(framework, [])
    findings = []
    for rule in rules:
        value = normalized.get(rule["field"])
        status = _check(value, rule["expected"])
        remediation = rule["remediation"].get(vendor, GENERIC_REMEDIATION) if status == "FAIL" else "-"
        risk = get_risk(rule["id"])
        ev_value = evidence.get(rule["field"])
        evidence_line = _evidence_line(ev_value, rule["field"])

        findings.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "status": status,
            "value": value,
            "expected": rule["expected"],
            "expected_text": rule.get("expected_text", _expected_text(rule["expected"])),
            "detected_text": _detected_text(value),
            "evidence": evidence_line,
            "source": _source_label(ev_value),
            "remediation": remediation,
            "remediation_meaning": rule.get("remediation_meaning", ""),
            "description": rule["description"],
            "why": risk["why"],
            "attack_path": risk["attack_path"],
            "framework": framework,
        })
    return findings


def summarize(findings, normalized=None):
    total = len(findings)
    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = total - passed
    by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f["status"] == "FAIL":
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    compliance_pct = round(100 * passed / total, 1) if total else 0.0

    hostname = None
    privileged_secret = None
    if normalized:
        hostname = normalized.get("hostname")
        privileged_secret = normalized.get("privileged_secret_configured")

    return {
        "total": total, "passed": passed, "failed": failed,
        "compliance_pct": compliance_pct, "fails_by_severity": by_severity,
        "hostname": hostname,
        "privileged_secret_configured": privileged_secret,
    }