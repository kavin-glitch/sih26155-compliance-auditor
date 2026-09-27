import json
import os
import threading

_LOCK = threading.Lock()
_PATH = os.path.join(os.path.dirname(__file__), "mappings.json")


def _load_all():
    if not os.path.exists(_PATH):
        return {}
    with open(_PATH, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save_all(data):
    with open(_PATH, "w") as f:
        json.dump(data, f, indent=2)


def _pattern_key(raw_line):
    tokens = raw_line.strip().lower().split()
    return " ".join(tokens[:3])


def _category_to_field(category_key):
    mapping = {
        "telnet_disable": "telnet_enabled",
        "telnet_enable": "telnet_enabled",
        "ssh_v2": "ssh_version",
        "http_disable": "http_mgmt_enabled",
        "https_enable": "https_mgmt_enabled",
        "password_encryption": "password_encryption",
        "min_password_length": "min_password_length",
        "banner": "banner_configured",
        "exec_timeout": "exec_timeout_minutes",
        "logging": "logging_enabled",
        "ntp": "ntp_configured",
        "aaa": "aaa_configured",
        "vty_acl": "vty_acl_applied",
        "snmp_weak": "weak_snmp_community_detected",
        "snmp_strong": "weak_snmp_community_detected",
        "lockout": "login_lockout_configured",
        "hostname": "hostname",
        "privileged_secret": "privileged_secret_configured",
        "ignored": "(no field - line is skipped)",
    }
    return mapping.get(category_key, "(unknown)")


def get_vendor_mappings(vendor):
    with _LOCK:
        data = _load_all()
    return data.get(vendor, {})


def learn(vendor, raw_line, category_key, example=None):
    key = _pattern_key(raw_line)
    with _LOCK:
        data = _load_all()
        data.setdefault(vendor, {})
        data[vendor][key] = {
            "category": category_key,
            "normalized_field": _category_to_field(category_key),
            "example": example or raw_line.strip(),
            "source": "human_confirmed",
        }
        _save_all(data)


def match(vendor, raw_line, vendor_mappings=None):
    mappings = vendor_mappings if vendor_mappings is not None else get_vendor_mappings(vendor)
    key = _pattern_key(raw_line)
    entry = mappings.get(key)
    if entry is None:
        return None
    if isinstance(entry, dict):
        return entry.get("category")
    return entry


def all_mappings():
    with _LOCK:
        return _load_all()


def reset(vendor=None):
    with _LOCK:
        data = _load_all()
        if vendor:
            data.pop(vendor, None)
        else:
            data = {}
        _save_all(data)