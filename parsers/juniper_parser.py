import re
from models.schema import default_normalized_dict, apply_category, is_ignorable
from ai import mapping_store

VENDOR = "juniper"


def parse(config_text: str):
    normalized = default_normalized_dict()
    evidence = {}
    unmatched = []
    learned = mapping_store.get_vendor_mappings(VENDOR)

    # Track whether we saw explicit telnet/http directives at all
    telnet_explicitly_disabled = False
    telnet_explicitly_enabled = False

    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if is_ignorable(line):
            continue

        matched = True

        if re.match(r"^set system host-name\b", line):
            m = re.search(r"host-name\s+\"?([A-Za-z0-9_\-\.]+)\"?", line)
            if m:
                normalized["hostname"] = m.group(1)
                evidence["hostname"] = raw

        # ---- Telnet: set = enabled, delete = explicitly disabled ----
        elif re.match(r"^set system services telnet\b", line):
            normalized["telnet_enabled"] = True
            evidence["telnet_enabled"] = raw
            telnet_explicitly_enabled = True
        elif re.match(r"^delete system services telnet\b", line):
            normalized["telnet_enabled"] = False
            evidence["telnet_enabled"] = raw
            telnet_explicitly_disabled = True

        elif "ssh" in line and ("protocol-version v2" in line or "root-login" in line):
            normalized["ssh_version"] = 2
            evidence["ssh_version"] = raw

        # ---- Web management: DELETE means disabled, SET means enabled ----
        elif re.match(r"^delete system services web-management http\b", line) or \
             re.match(r"^delete system services web-management\b.*\bhttp\b(?!s)", line):
            normalized["http_mgmt_enabled"] = False
            evidence["http_mgmt_enabled"] = raw
        elif re.match(r"^set system services web-management http\b", line) and "https" not in line:
            normalized["http_mgmt_enabled"] = True
            evidence["http_mgmt_enabled"] = raw
        elif "web-management https" in line and line.startswith("set"):
            normalized["https_mgmt_enabled"] = True
            evidence["https_mgmt_enabled"] = raw
        elif re.match(r"^delete system services web-management https\b", line):
            normalized["https_mgmt_enabled"] = False
            evidence["https_mgmt_enabled"] = raw

        elif "encrypted-password" in line:
            normalized["password_encryption"] = True
            evidence["password_encryption"] = raw

        elif "password minimum-length" in line:
            m = re.search(r"minimum-length (\d+)", line)
            if m:
                normalized["min_password_length"] = int(m.group(1))
                evidence["min_password_length"] = raw

        elif "login message" in line or "login announcement" in line:
            normalized["banner_configured"] = True
            evidence["banner_configured"] = raw

        elif "idle-timeout" in line:
            m = re.search(r"idle-timeout (\d+)", line)
            if m:
                normalized["exec_timeout_minutes"] = int(m.group(1))
                evidence["exec_timeout_minutes"] = raw

        elif "set system syslog" in line:
            normalized["logging_enabled"] = True
            evidence["logging_enabled"] = raw

        elif "set system ntp server" in line:
            normalized["ntp_configured"] = True
            evidence["ntp_configured"] = raw

        elif "authentication-order" in line:
            normalized["aaa_configured"] = True
            evidence["aaa_configured"] = raw

        elif "family inet filter input" in line or "firewall filter" in line:
            normalized["vty_acl_applied"] = True
            evidence["vty_acl_applied"] = raw

        elif "snmp community" in line:
            if re.search(r"\b(public|private)\b", line):
                normalized["weak_snmp_community_detected"] = True
                evidence["weak_snmp_community_detected"] = raw
            else:
                normalized["weak_snmp_community_detected"] = False
                evidence.setdefault("weak_snmp_community_detected", raw)

        elif "retry-options" in line and "tries-before-disconnect" in line:
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

    # ---- Junos default-state inference ----
    # On Junos, if we never saw `set system services telnet`, Telnet is disabled by default.
    if normalized["telnet_enabled"] is None and not telnet_explicitly_enabled:
        normalized["telnet_enabled"] = False
        evidence["telnet_enabled"] = "(platform default: Junos disables Telnet unless explicitly enabled via 'set system services telnet')"

    # Same for HTTP management: if we never saw a `set ... web-management http` and never
    # saw an explicit delete, it defaults to disabled.
    if normalized["http_mgmt_enabled"] is None:
        normalized["http_mgmt_enabled"] = False
        evidence["http_mgmt_enabled"] = "(platform default: Junos web-management HTTP is off unless explicitly enabled)"

    return normalized, evidence, unmatched