import os

import streamlit as st

from parsers import vendor_detector, cisco_parser, juniper_parser, fortinet_parser, generic_parser
from compliance import engine
from compliance.rules import FRAMEWORKS
from ai import unknown_command_ai, mapping_store
from reporting import pdf_report

st.set_page_config(page_title="AI-Driven Multi-Vendor Compliance Auditor", layout="wide")

PARSERS = {
    "cisco": cisco_parser.parse,
    "juniper": juniper_parser.parse,
    "fortinet": fortinet_parser.parse,
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def parse_config(config_text, forced_vendor_label=None):
    vendor = vendor_detector.detect(config_text)
    if vendor == "unknown":
        label = forced_vendor_label or "unknown"
        normalized, evidence, unmatched = generic_parser.parse(config_text, vendor_label=label)
        return label, normalized, evidence, unmatched
    normalized, evidence, unmatched = PARSERS[vendor](config_text)
    return vendor, normalized, evidence, unmatched


def _source_from_evidence(ev):
    if ev is None:
        return "not present in config"
    if "(platform default" in ev or "(system default" in ev:
        return "platform default"
    if "(learned mapping" in ev or "(confirmed mapping" in ev:
        return "learned mapping (human-confirmed)"
    return "config line"


def render_normalized_model(normalized, evidence=None):
    st.markdown("##### Universal Security Model (normalized)")
    st.caption("Every vendor's config is reduced to this same vendor-agnostic view before compliance rules run. "
               "Each field shows its value, the raw source, and whether it came from a config line, "
               "a platform default, or a learned mapping.")

    display = {k: v for k, v in normalized.items() if v is not None}
    if not display:
        st.info("No fields extracted yet.")
        return

    items = list(display.items())
    for i in range(0, len(items), 2):
        cols = st.columns(2)
        for j in range(2):
            if i + j >= len(items):
                break
            k, v = items[i + j]
            with cols[j]:
                with st.container(border=True):
                    st.markdown(f"**{k}**")
                    st.markdown(f"Normalized value: `{v}`")
                    src = evidence.get(k) if evidence else None
                    source_kind = _source_from_evidence(src)
                    st.caption(f"Source: **{source_kind}**")
                    if src:
                        st.code(src, language="text")


def render_findings(findings, key_prefix):
    findings_sorted = sorted(findings, key=lambda f: (f["status"] != "FAIL", SEVERITY_ORDER.get(f["severity"], 9)))
    for f in findings_sorted:
        icon = "🔴" if f["status"] == "FAIL" else "🟢"
        with st.expander(f"{icon} [{f['id']}] {f['name']}  -  {f['severity']} severity  -  {f['status']}"):
            col1, col2 = st.columns([1, 1])
            with col1:
                st.markdown(f"**Status:** {'FAIL' if f['status']=='FAIL' else 'PASS'}")
                st.markdown(f"**Severity:** {f['severity']}")
                st.markdown(f"**Framework:** {f.get('framework','CIS')}")
                st.markdown(f"**Source:** {f.get('source','-')}")
            with col2:
                st.markdown("**Evidence from config:**")
                st.code(f["evidence"], language="text")

            st.markdown(f"**Description:** {f['description']}")

            ec1, ec2 = st.columns(2)
            with ec1:
                st.markdown("**Detected:**")
                st.write(f.get("detected_text", "-"))
            with ec2:
                st.markdown("**Expected:**")
                st.write(f.get("expected_text", "-"))

            if f["status"] == "FAIL":
                st.markdown("---")
                st.markdown("**Why is this dangerous?**")
                st.write(f.get("why", ""))
                ap = f.get("attack_path") or []
                if ap:
                    st.markdown("**Potential attack path** (illustrative — not a proven exploit):")
                    st.markdown("\n\n⬇️\n\n".join(f"`{step}`" for step in ap))
                st.markdown("---")
                st.markdown("**Remediation (vendor-specific):**")
                st.code(f["remediation"], language="bash")
                if f.get("remediation_meaning"):
                    st.caption(f"Meaning: {f['remediation_meaning']}")


def render_training_ui(vendor_label, unmatched_lines, session_key, config_text=None, framework="CIS"):
    if not unmatched_lines:
        st.success("No unrecognized lines - every line in this config was understood.")
        return

    st.warning(f"{len(unmatched_lines)} line(s) were not recognized. Teach the system below.")
    for i, raw in enumerate(unmatched_lines):
        suggestions = unknown_command_ai.suggest(raw)
        top_label, top_conf = (suggestions[0][1], suggestions[0][2]) if suggestions else ("No confident suggestion", 0)

        with st.container(border=True):
            st.markdown("##### Unknown Configuration")
            st.code(raw, language="text")

            if suggestions:
                st.markdown(f"**AI Interpretation**  \n"
                            f"Suggested meaning: **{top_label}**  \n"
                            f"Confidence: **{top_conf}%**")
            else:
                st.markdown("**AI has no confident suggestion** — this may be structural or irrelevant syntax. "
                            "Default is **'Not security-relevant — ignore this line'**.")

            choices = unknown_command_ai.category_choices()
            labels = [c[1] for c in choices]
            keys = [c[0] for c in choices]
            default_idx = keys.index(suggestions[0][0]) if suggestions else keys.index("ignored")

            col1, col2 = st.columns([3, 1])
            with col1:
                chosen_label = st.selectbox(
                    "Confirm what this line configures:",
                    labels, index=default_idx,
                    key=f"{session_key}_{i}_select",
                )
            with col2:
                if st.button("Accept & Learn", key=f"{session_key}_{i}_confirm"):
                    category_key = keys[labels.index(chosen_label)]
                    mapping_store.learn(vendor_label, raw, category_key, example=raw.strip())
                    st.success("Mapping saved. Click 'Re-run Audit' below.")
                    st.rerun()

    if config_text is not None:
        st.markdown("---")
        if st.button("🔄 Re-run Audit with learned mappings", type="primary", key=f"{session_key}_rerun_btn"):
            rerun_vendor, normalized2, evidence2, unmatched2 = parse_config(
                config_text, forced_vendor_label=vendor_label
            )
            findings2 = engine.evaluate(normalized2, evidence2, rerun_vendor, framework)
            summary2 = engine.summarize(findings2, normalized2)
            st.session_state[f"{session_key}_rerun"] = {
                "summary": summary2, "findings": findings2, "normalized": normalized2,
                "unmatched": unmatched2, "vendor": rerun_vendor, "evidence": evidence2,
            }
            st.rerun()

    rerun_key = f"{session_key}_rerun"
    if rerun_key in st.session_state:
        r = st.session_state[rerun_key]
        st.success(f"Re-audit: **{r['summary']['compliance_pct']}%** "
                   f"({r['summary']['passed']} / {r['summary']['total']}), "
                   f"**{len(r['unmatched'])}** still unrecognized.")
        with st.expander("View re-audit findings", expanded=True):
            render_findings(r["findings"], f"{session_key}_rerun_find")
        with st.expander("View updated Normalized Model", expanded=False):
            render_normalized_model(r["normalized"], r.get("evidence"))


def audit_device(uf, framework, key_prefix):
    config_text = uf.getvalue().decode("utf-8", errors="ignore")
    vendor, normalized, evidence, unmatched = parse_config(config_text)

    badge = f"  |  ⚠ {len(unmatched)} unrecognized" if unmatched else ""
    st.markdown(f"### {uf.name}{badge}")
    st.caption(f"Detected vendor: **{vendor.capitalize()}**")

    findings = engine.evaluate(normalized, evidence, vendor, framework)
    summary = engine.summarize(findings, normalized)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Compliance", f"{summary['compliance_pct']}%",
              help=f"{summary['passed']} / {summary['total']} controls passed")
    c2.metric("Passed", f"{summary['passed']} / {summary['total']}")
    c3.metric("Failed", summary["failed"])
    c4.metric("High-Sev Fails", summary["fails_by_severity"].get("High", 0))
    st.caption(f"Compliance = {summary['passed']} / {summary['total']} controls passed = {summary['compliance_pct']}%")

    tab1, tab2, tab3 = st.tabs(["Findings", "Normalized Model", "Unknown Command Training"])
    with tab1:
        render_findings(findings, f"{key_prefix}_find")
        if st.button("Generate PDF Report", key=f"{key_prefix}_pdf"):
            path = f"outputs/{uf.name}_report.pdf"
            pdf_report.generate_device_report(path, uf.name, vendor, framework, findings, summary)
            with open(path, "rb") as f:
                st.download_button("Download PDF Report", f, file_name=os.path.basename(path),
                                   key=f"{key_prefix}_dl")
    with tab2:
        render_normalized_model(normalized, evidence)
    with tab3:
        render_training_ui(vendor, unmatched, f"{key_prefix}_train",
                           config_text=config_text, framework=framework)

    return {"name": uf.name, "vendor": vendor, "summary": summary}


# ---------------------------------------------------------------- SIDEBAR --
st.sidebar.title("Compliance Auditor")
mode = st.sidebar.radio("Mode", ["Audit", "Train Unknown Vendor", "Learned Mappings"])
framework = st.sidebar.selectbox("Framework", list(FRAMEWORKS.keys()))
st.sidebar.markdown("---")
st.sidebar.caption("AI-Driven Multi-Vendor Network Security Compliance Auditor\nSIH26155 - NTRO")
st.sidebar.info("AI understands. Rules decide.\n\nAI suggests interpretations of unfamiliar syntax. "
                "The deterministic engine makes every PASS/FAIL call.")

os.makedirs("outputs", exist_ok=True)

# ----------------------------------------------------------------- AUDIT ---
if mode == "Audit":
    st.title("Multi-Vendor Network Security Audit")
    st.caption("Upload one config or many — from any vendor. Each is normalized to the same security model, "
               "audited against the selected framework, and reported with evidence + remediation.")

    uploaded_files = st.file_uploader(
        "Upload device configuration file(s)",
        type=["cfg", "txt", "conf"],
        accept_multiple_files=True,
    )

    if uploaded_files:
        if len(uploaded_files) > 1:
            st.subheader(f"Fleet Overview ({len(uploaded_files)} devices)")
            summary_rows = []
            device_infos = []
            for uf in uploaded_files:
                config_text = uf.getvalue().decode("utf-8", errors="ignore")
                vendor, normalized, evidence, unmatched = parse_config(config_text)
                findings = engine.evaluate(normalized, evidence, vendor, framework)
                summary = engine.summarize(findings, normalized)
                high = summary["fails_by_severity"].get("High", 0)
                status = "OK" if summary["compliance_pct"] >= 80 else ("WARN" if summary["compliance_pct"] >= 60 else "HIGH RISK")
                summary_rows.append({
                    "Device": uf.name,
                    "Hostname": summary.get("hostname") or "-",
                    "Vendor": vendor.capitalize(),
                    "Score": f"{summary['compliance_pct']}%",
                    "Passed": f"{summary['passed']} / {summary['total']}",
                    "High Risk": high,
                    "Unrecognized": len(unmatched),
                    "Status": status,
                })
                device_infos.append({"name": uf.name, "vendor": vendor, "summary": summary})

            st.dataframe(summary_rows, width="stretch")

            avg = round(sum(d["summary"]["compliance_pct"] for d in device_infos) / len(device_infos), 1)
            st.metric("Average Compliance Across Fleet", f"{avg}%")

            if st.button("Generate Organization Dashboard PDF"):
                path = "outputs/organization_dashboard.pdf"
                pdf_report.generate_dashboard_report(path, device_infos)
                with open(path, "rb") as f:
                    st.download_button("Download Dashboard PDF", f, file_name="organization_dashboard.pdf")

            st.markdown("---")
            st.subheader("Per-Device Detail")

        for i, uf in enumerate(uploaded_files):
            if len(uploaded_files) > 1:
                with st.container(border=True):
                    audit_device(uf, framework, key_prefix=f"dev_{i}")
            else:
                audit_device(uf, framework, key_prefix=f"dev_{i}")

# ------------------------------------------------------- TRAIN UNKNOWN -----
elif mode == "Train Unknown Vendor":
    st.title("Train the System on a New / Unrecognized Vendor")
    st.caption("Unknown syntax -> AI suggests -> human confirms -> mapping saved -> audit re-runs with new knowledge.")

    vendor_label = st.text_input("Vendor / device family label (e.g. 'edgecore', 'mikrotik')", value="unknown")
    uploaded = st.file_uploader("Upload a config from this unrecognized vendor",
                                type=["cfg", "txt", "conf"], key="train_upload")

    if uploaded:
        config_text = uploaded.getvalue().decode("utf-8", errors="ignore")
        normalized, evidence, unmatched = generic_parser.parse(config_text, vendor_label=vendor_label)

        findings = engine.evaluate(normalized, evidence, vendor_label, framework)
        summary = engine.summarize(findings, normalized)

        c1, c2, c3 = st.columns(3)
        c1.metric("Current Compliance", f"{summary['compliance_pct']}%",
                  help=f"{summary['passed']} / {summary['total']} controls passed")
        c2.metric("Lines Unrecognized", len(unmatched))
        c3.metric("Lines Understood", len(config_text.splitlines()) - len(unmatched))

        render_training_ui(vendor_label, unmatched, "gen_train", config_text=config_text, framework=framework)

        if not unmatched:
            with st.expander("View Findings", expanded=True):
                render_findings(findings, "train_findings")
            with st.expander("View Normalized Model", expanded=False):
                render_normalized_model(normalized, evidence)

# ------------------------------------------------------- LEARNED MAPPINGS --
elif mode == "Learned Mappings":
    st.title("Learned Mappings (Persisted Knowledge)")
    st.caption("Every confirmed mapping is stored here and reused on future uploads. "
               "Each entry shows: command pattern, category, normalized field, source.")

    data = mapping_store.all_mappings()
    if not data:
        st.info("No mappings learned yet. Go to 'Train Unknown Vendor' to teach the system a new syntax.")
    else:
        choices = unknown_command_ai.category_choices()
        labels = [c[1] for c in choices]
        keys = [c[0] for c in choices]

        for vendor, mappings in data.items():
            st.subheader(f"Vendor: {vendor}")

            rows = []
            for pattern, entry in mappings.items():
                if isinstance(entry, dict):
                    cat = entry.get("category", "?")
                    field = entry.get("normalized_field", "?")
                    example = entry.get("example", "")
                    source = entry.get("source", "human_confirmed")
                else:
                    cat = entry
                    field = "(not recorded)"
                    example = ""
                    source = "legacy"
                rows.append({
                    "Command pattern": pattern,
                    "Category": cat,
                    "Normalized field": field,
                    "Example": example,
                    "Source": source,
                })
            st.dataframe(rows, width="stretch")

            with st.expander(f"Edit / delete entries for {vendor}"):
                for pattern, entry in list(mappings.items()):
                    current_cat = entry.get("category") if isinstance(entry, dict) else entry
                    col1, col2, col3 = st.columns([3, 4, 1])
                    with col1:
                        st.code(pattern, language="text")
                    with col2:
                        current_idx = keys.index(current_cat) if current_cat in keys else 0
                        new_label = st.selectbox(
                            "Maps to", labels, index=current_idx,
                            key=f"edit_{vendor}_{pattern}", label_visibility="collapsed",
                        )
                        new_cat = keys[labels.index(new_label)]
                    with col3:
                        if new_cat != current_cat:
                            if st.button("💾", key=f"save_{vendor}_{pattern}"):
                                example = entry.get("example", "") if isinstance(entry, dict) else ""
                                mapping_store.learn(vendor, pattern, new_cat, example=example)
                                st.rerun()
                        if st.button("🗑️", key=f"del_{vendor}_{pattern}"):
                            all_data = mapping_store.all_mappings()
                            if vendor in all_data and pattern in all_data[vendor]:
                                del all_data[vendor][pattern]
                                if not all_data[vendor]:
                                    del all_data[vendor]
                            import json as _json
                            with open(os.path.join(os.path.dirname(mapping_store.__file__), "mappings.json"), "w") as f:
                                _json.dump(all_data, f, indent=2)
                            st.rerun()

        st.markdown("---")
        if st.button("🗑️ Reset ALL learned mappings"):
            mapping_store.reset()
            st.rerun()