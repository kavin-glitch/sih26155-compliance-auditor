"""
Common Security Model (normalized schema).
"""

import re

FIELDS = [
    "telnet_enabled",
    "ssh_version",
    "http_mgmt_enabled",
    "https_mgmt_enabled",
    "password_encryption",
    "min_password_length",
    "banner_configured",
    "exec_timeout_minutes",
    "logging_enabled",
    "ntp_configured",
    "aaa_configured",
    "vty_acl_applied",
    "weak_snmp_community_detected",
    "login_lockout_configured",
]

DEVICE_INFO_FIELDS = ["hostname", "privileged_secret_configured"]


def default_normalized_dict():
    d = {field: None for field in FIELDS}
    d.update({field: None for field in DEVICE_INFO_FIELDS})
    return d


def _extract_int(line, default):
    m = re.search(r"(\d+)", line)
    return int(m.group(1)) if m else default


def _extract_hostname(line):
    m = re.search(r"host-?name\s+\"?([A-Za-z0-9_\-\.]+)\"?", line, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"name[=\s]+\"?([A-Za-z0-9_\-\.]+)\"?", line, re.IGNORECASE)
    if m:
        return m.group(1)
    return "unknown"


IGNORE_PATTERNS = [
    r"^end$",
    r"^exit$",
    r"^!+$",
    r"^#.*$",
    r"^\s*$",
    r"^commit$",
    r"^quit$",
]


def is_ignorable(line: str) -> bool:
    s = line.strip().lower()
    for p in IGNORE_PATTERNS:
        if re.match(p, s):
            return True
    return False


CATEGORY_ACTIONS = {
    "telnet_disable": (
        "Disables Telnet access",
        lambda norm, ev, raw: (norm.__setitem__("telnet_enabled", False), ev.__setitem__("telnet_enabled", raw)),
    ),
    "telnet_enable": (
        "Enables Telnet access (insecure)",
        lambda norm, ev, raw: (norm.__setitem__("telnet_enabled", True), ev.__setitem__("telnet_enabled", raw)),
    ),
    "ssh_v2": (
        "Enables/enforces SSH version 2",
        lambda norm, ev, raw: (norm.__setitem__("ssh_version", 2), ev.__setitem__("ssh_version", raw)),
    ),
    "http_disable": (
        "Disables HTTP management",
        lambda norm, ev, raw: (norm.__setitem__("http_mgmt_enabled", False), ev.__setitem__("http_mgmt_enabled", raw)),
    ),
    "https_enable": (
        "Enables HTTPS management",
        lambda norm, ev, raw: (norm.__setitem__("https_mgmt_enabled", True), ev.__setitem__("https_mgmt_enabled", raw)),
    ),
    "password_encryption": (
        "Configures password encryption",
        lambda norm, ev, raw: (norm.__setitem__("password_encryption", True), ev.__setitem__("password_encryption", raw)),
    ),
    "min_password_length": (
        "Sets minimum password length",
        lambda norm, ev, raw: (norm.__setitem__("min_password_length", _extract_int(raw, 8)), ev.__setitem__("min_password_length", raw)),
    ),
    "banner": (
        "Configures a login/MOTD banner",
        lambda norm, ev, raw: (norm.__setitem__("banner_configured", True), ev.__setitem__("banner_configured", raw)),
    ),
    "exec_timeout": (
        "Sets session/idle timeout (in minutes)",
        lambda norm, ev, raw: (norm.__setitem__("exec_timeout_minutes", _extract_int(raw, 10)), ev.__setitem__("exec_timeout_minutes", raw)),
    ),
    "logging": (
        "Enables logging / syslog",
        lambda norm, ev, raw: (norm.__setitem__("logging_enabled", True), ev.__setitem__("logging_enabled", raw)),
    ),
    "ntp": (
        "Configures NTP / time sync",
        lambda norm, ev, raw: (norm.__setitem__("ntp_configured", True), ev.__setitem__("ntp_configured", raw)),
    ),
    "aaa": (
        "Configures centralized authentication (AAA/RADIUS/TACACS+)",
        lambda norm, ev, raw: (norm.__setitem__("aaa_configured", True), ev.__setitem__("aaa_configured", raw)),
    ),
    "vty_acl": (
        "Restricts management access via ACL",
        lambda norm, ev, raw: (norm.__setitem__("vty_acl_applied", True), ev.__setitem__("vty_acl_applied", raw)),
    ),
    "snmp_weak": (
        "Detected weak/default SNMP community string (public/private)",
        lambda norm, ev, raw: (norm.__setitem__("weak_snmp_community_detected", True), ev.__setitem__("weak_snmp_community_detected", raw)),
    ),
    "snmp_strong": (
        "Sets a non-default SNMP community string",
        lambda norm, ev, raw: (norm.__setitem__("weak_snmp_community_detected", False), ev.__setitem__("weak_snmp_community_detected", raw)),
    ),
    "lockout": (
        "Configures account lockout / login retry limit",
        lambda norm, ev, raw: (norm.__setitem__("login_lockout_configured", True), ev.__setitem__("login_lockout_configured", raw)),
    ),
    "hostname": (
        "Sets device hostname / identity (informational only)",
        lambda norm, ev, raw: (norm.__setitem__("hostname", _extract_hostname(raw)), ev.__setitem__("hostname", raw)),
    ),
    "privileged_secret": (
        "Configures privileged (enable) secret / admin credentials",
        lambda norm, ev, raw: (norm.__setitem__("privileged_secret_configured", True), ev.__setitem__("privileged_secret_configured", raw)),
    ),
    "ignored": (
        "Not security-relevant — ignore this line",
        lambda norm, ev, raw: (None, None),
    ),
}


def apply_category(normalized, evidence, category_key, raw_line):
    if category_key in CATEGORY_ACTIONS:
        _, fn = CATEGORY_ACTIONS[category_key]
        fn(normalized, evidence, raw_line)
        return True
    return False