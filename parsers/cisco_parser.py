import re
from models.schema import default_normalized_dict, apply_category, is_ignorable
from ai import mapping_store

VENDOR = "cisco"


def parse(config_text: str):
    normalized = default_normalized_dict()
    evidence = {}
    unmatched = []
    learned = mapping_store.get_vendor_mappings(VENDOR)

    in_vty = False
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            in_vty = False
            continue
        if is_ignorable(line):
            continue

        matched = True
        if re.match(r"^line vty\b", line):
            in_vty = True
        elif re.match(r"^line con\b", line):
            in_vty = False
        elif line.startswith("hostname "):
            m = re.search(r"hostname\s+(\S+)", line)
            if m:
                normalized["hostname"] = m.group(1)
                evidence["hostname"] = raw
        elif line.startswith("enable secret") or line.startswith("enable password"):
            normalized["privileged_secret_configured"] = True
            evidence["privileged_secret_configured"] = raw
        elif "transport input" in line:
            if "telnet" in line:
                normalized["telnet_enabled"] = True
                evidence["telnet_enabled"] = raw
            elif "ssh" in line:
                normalized["telnet_enabled"] = False
                evidence.setdefault("telnet_enabled", raw)
        elif line.startswith("ip ssh version"):
            m = re.search(r"ip ssh version (\d)", line)
            if m:
                normalized["ssh_version"] = int(m.group(1))
                evidence["ssh_version"] = raw
        elif line == "no ip http server":
            normalized["http_mgmt_enabled"] = False
            evidence["http_mgmt_enabled"] = raw
        elif line == "ip http server":
            normalized["http_mgmt_enabled"] = True
            evidence["http_mgmt_enabled"] = raw
        elif line.startswith("ip http secure-server"):
            normalized["https_mgmt_enabled"] = True
            evidence["https_mgmt_enabled"] = raw
        elif line.startswith("service password-encryption"):
            normalized["password_encryption"] = True
            evidence["password_encryption"] = raw
        elif line.startswith("security passwords min-length"):
            m = re.search(r"min-length (\d+)", line)
            if m:
                normalized["min_password_length"] = int(m.group(1))
                evidence["min_password_length"] = raw
        elif line.startswith("banner motd") or line.startswith("banner login"):
            normalized["banner_configured"] = True
            evidence["banner_configured"] = raw
        elif line.startswith("exec-timeout") and in_vty:
            m = re.search(r"exec-timeout (\d+)", line)
            if m:
                normalized["exec_timeout_minutes"] = int(m.group(1))
                evidence["exec_timeout_minutes"] = raw
        elif line.startswith("logging buffered") or line.startswith("logging host") or line.startswith("logging trap"):
            normalized["logging_enabled"] = True
            evidence["logging_enabled"] = raw
        elif line.startswith("ntp server"):
            normalized["ntp_configured"] = True
            evidence["ntp_configured"] = raw
        elif line.startswith("aaa new-model"):
            normalized["aaa_configured"] = True
            evidence["aaa_configured"] = raw
        elif line.startswith("access-class") and in_vty:
            normalized["vty_acl_applied"] = True
            evidence["vty_acl_applied"] = raw
        elif line.startswith("snmp-server community"):
            if re.search(r"\b(public|private)\b", line):
                normalized["weak_snmp_community_detected"] = True
                evidence["weak_snmp_community_detected"] = raw
            else:
                normalized["weak_snmp_community_detected"] = False
                evidence.setdefault("weak_snmp_community_detected", raw)
        elif line.startswith("login block-for"):
            normalized["login_lockout_configured"] = True
            evidence["login_lockout_configured"] = raw
        else:
            matched = False

        if not matched:
            category = mapping_store.match(VENDOR, raw, learned)
            if category:
                apply_category(normalized, evidence, category, raw)
            else:
                unmatched.append(raw)

    return normalized, evidence, unmatched