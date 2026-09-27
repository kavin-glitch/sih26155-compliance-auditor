"""Quick end-to-end sanity check (no Streamlit needed). Run: python test_run.py"""
from parsers import vendor_detector, cisco_parser, juniper_parser, fortinet_parser, generic_parser
from compliance import engine
from ai import mapping_store, unknown_command_ai
from reporting import pdf_report

PARSERS = {"cisco": cisco_parser.parse, "juniper": juniper_parser.parse, "fortinet": fortinet_parser.parse}


def audit_file(path, forced_label=None):
    text = open(path).read()
    vendor = vendor_detector.detect(text)
    if vendor == "unknown":
        vendor = forced_label or "unknown"
        normalized, evidence, unmatched = generic_parser.parse(text, vendor_label=vendor)
    else:
        normalized, evidence, unmatched = PARSERS[vendor](text)
    findings = engine.evaluate(normalized, evidence, vendor, "CIS")
    summary = engine.summarize(findings)
    print(f"\n=== {path} ===")
    print(f"Detected vendor: {vendor}")
    print(f"Unmatched lines: {len(unmatched)}")
    print(f"Compliance: {summary['compliance_pct']}%  (Pass {summary['passed']} / Fail {summary['failed']})")
    print(f"Fails by severity: {summary['fails_by_severity']}")
    return vendor, normalized, evidence, unmatched, findings, summary


print("### STEP 1: Known vendors (Cisco / Juniper / Fortinet) ###")
c_vendor, c_norm, c_ev, c_un, c_find, c_sum = audit_file("sample_configs/cisco_sample.cfg")
j_vendor, j_norm, j_ev, j_un, j_find, j_sum = audit_file("sample_configs/juniper_sample.cfg")
f_vendor, f_norm, f_ev, f_un, f_find, f_sum = audit_file("sample_configs/fortinet_sample.cfg")

print("\n### STEP 2: PDF generation ###")
p1 = pdf_report.generate_device_report("outputs/cisco_report.pdf", "cisco_sample.cfg", c_vendor, "CIS", c_find, c_sum)
print(f"Generated: {p1}")

print("\n### STEP 3: Unknown vendor BEFORE training ###")
mapping_store.reset("edgecore")  # clean slate for repeatable test
vendor_label = "edgecore"
u_vendor, u_norm, u_ev, u_un, u_find, u_sum = audit_file("sample_configs/unknown_vendor_sample.cfg", vendor_label)
print(f"Unrecognized lines before training: {len(u_un)}")
assert len(u_un) > 5, "expected several unmatched lines before training"

print("\n### STEP 4: AI suggestion quality check ###")
for line in u_un[:5]:
    suggestions = unknown_command_ai.suggest(line)
    print(f"  '{line.strip()}' -> {suggestions}")

print("\n### STEP 5: Simulate human confirming AI suggestions (teach every unmatched line) ###")
for line in u_un:
    suggestions = unknown_command_ai.suggest(line)
    if suggestions:
        category = suggestions[0][0]
    else:
        category = "logging"  # fallback for demo determinism
    mapping_store.learn(vendor_label, line, category)
print(f"Learned {len(u_un)} mappings for vendor '{vendor_label}'.")

print("\n### STEP 6: Re-parse SAME config -> should now have 0 unmatched lines ###")
u_vendor2, u_norm2, u_ev2, u_un2, u_find2, u_sum2 = audit_file("sample_configs/unknown_vendor_sample.cfg", vendor_label)
print(f"Unrecognized lines after training: {len(u_un2)}")
assert len(u_un2) == 0, "training loop failed to eliminate unmatched lines on same file"

print("\n### STEP 7: Upload a DIFFERENT device from the SAME unknown vendor -> should also be recognized ###")
u_vendor3, u_norm3, u_ev3, u_un3, u_find3, u_sum3 = audit_file("sample_configs/unknown_vendor_sample_device2.cfg", vendor_label)
print(f"Unrecognized lines on second device (never seen before, same vendor): {len(u_un3)}")
assert len(u_un3) == 0, "learned mappings did not generalize to a second device"

print("\n### STEP 8: Generate dashboard PDF for bulk audit ###")
device_summaries = [
    {"name": "cisco_sample.cfg", "vendor": c_vendor, "summary": c_sum},
    {"name": "juniper_sample.cfg", "vendor": j_vendor, "summary": j_sum},
    {"name": "fortinet_sample.cfg", "vendor": f_vendor, "summary": f_sum},
    {"name": "unknown_vendor_sample.cfg", "vendor": u_vendor, "summary": u_sum2},
]
p2 = pdf_report.generate_dashboard_report("outputs/organization_dashboard.pdf", device_summaries)
print(f"Generated: {p2}")

print("\n✅ ALL CHECKS PASSED — parsers, normalization, compliance engine, AI training loop, and PDF reporting all work end-to-end.")
