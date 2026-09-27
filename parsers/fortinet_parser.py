import re
from models.schema import default_normalized_dict, apply_category, is_ignorable
from ai import mapping_store

VENDOR = "fortinet"


def parse(config_text: str):
    normalized = default_normalized_dict()
    evidence = {}
    unmatched = []
    learned = mapping_store.get_vendor_mappings(VENDOR)

    in_log_block = False
    in_ntp_block = False
    in_snmp_block = False

    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if is_ignorable(line):
            continue

        if re.match(r"^config log\b", line):
            in_log_block = True
            in_ntp_block = in_snmp_block = False
            continue
        if re.match(r"^config system ntp\b", line):
            in_ntp_block = True
            in_log_block = in_snmp_block = False
            continue
        if re.match(r"^config system snmp\b", line):
            in_snmp_block = True
            in_log_block = in_ntp_block = False
            continue
        if re.match(r"^config ", line):
            in_log_block = in_ntp_block = in_snmp_block = False
            continue
        if re.match(r"^(end|next)\b", line):
            in_log_block = in_ntp_block = in_snmp_block = False
            continue

        matched = True

        if re.match(r'^set hostname\b', line):
            m = re.search(r'set hostname\s+"?([A-Za-z0-9_\-]+)"?', line)
            if m:
                normalized["hostname"] = m.group(1)
                evidence["hostname"] = raw

        elif re.match(r"^set allowaccess\b", line):
            low = line.lower()
            if "telnet" in low:
                normalized["telnet_enabled"] = True
                evidence["telnet_enabled"] = raw
            else:
                if normalized["telnet_enabled"] is None:
                    normalized["telnet_enabled"] = False
                    evidence.setdefault("telnet_enabled", raw)
            if "https" in low:
                normalized["https_mgmt_enabled"] = True
                evidence["https_mgmt_enabled"] = raw
            if re.search(r"(?<![a-z])http(?![a-z])", low):
                normalized["http_mgmt_enabled"] = True
                evidence["http_mgmt_enabled"] = raw
            else:
                if normalized["http_mgmt_enabled"] is None:
                    normalized["http_mgmt_enabled"] = False
                    evidence.setdefault("http_mgmt_enabled", raw)
            if "ssh" in low:
                normalized["ssh_version"] = 2
                evidence["ssh_version"] = raw

        elif "set admin-lockout-threshold" in line:
            normalized["login_lockout_configured"] = True
            evidence["login_lockout_configured"] = raw

        elif "set admintimeout" in line:
            m = re.search(r"set admintimeout (\d+)", line)
            if m:
                normalized["exec_timeout_minutes"] = int(m.group(1))
                evidence["exec_timeout_minutes"] = raw

        elif "set pre-login-banner" in line or "set post-login-banner" in line:
            if "enable" in line:
                normalized["banner_configured"] = True
                evidence["banner_configured"] = raw

        elif "set minimum-length" in line:
            m = re.search(r"set minimum-length (\d+)", line)
            if m:
                normalized["min_password_length"] = int(m.group(1))
                evidence["min_password_length"] = raw

        elif in_log_block and "set status enable" in line:
            normalized["logging_enabled"] = True
            evidence["logging_enabled"] = raw

        elif in_ntp_block and "set ntpsync enable" in line:
            normalized["ntp_configured"] = True
            evidence["ntp_configured"] = raw

        elif re.match(r"^set auth-type\b", line) or re.match(r"^set radius-server\b", line):
            normalized["aaa_configured"] = True
            evidence["aaa_configured"] = raw

        elif "set trusthost" in line:
            normalized["vty_acl_applied"] = True
            evidence["vty_acl_applied"] = raw

        elif in_snmp_block and "set name" in line and re.search(r"\b(public|private)\b", line.lower()):
            normalized["weak_snmp_community_detected"] = True
            evidence["weak_snmp_community_detected"] = raw

        elif in_snmp_block and "set name" in line:
            normalized["weak_snmp_community_detected"] = False
            evidence.setdefault("weak_snmp_community_detected", raw)

        elif "encrypt" in line and "password" in line:
            normalized["password_encryption"] = True
            evidence["password_encryption"] = raw

        elif re.match(r"^set (server|radius-server|secondary-server|source-ip)\b", line):
            pass

        else:
            matched = False

        if not matched:
            category = mapping_store.match(VENDOR, raw, learned)
            if category:
                apply_category(normalized, evidence, category, raw)
            else:
                unmatched.append(raw)

    if normalized["password_encryption"] is None:
        normalized["password_encryption"] = True
        evidence.setdefault("password_encryption", "(platform default: FortiOS stores admin passwords encrypted)")

    return normalized, evidence, unmatched