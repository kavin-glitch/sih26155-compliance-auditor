"""
AI interpretation layer for unrecognized configuration lines.

Keyword + pattern scoring. Deterministic, offline, auditable.
The AI never decides compliance — it only proposes what a line *means*.
"""

import re
from models.schema import CATEGORY_ACTIONS, is_ignorable

# Ordered rules. More specific patterns first.
_KEYWORD_RULES = [
    # --- Lockout / login retry (put BEFORE logging so 'retry-limit' wins) ---
    (r"login[-_ ]?retry|retry[-_ ]?limit|lockout|block-for|tries[-_ ]?before|"
     r"admin[-_ ]?lockout|failed[-_ ]?login", "lockout", 1.0),

    # --- Hostname / identity (put BEFORE ssh so 'host-name' wins) ---
    (r"^hostname\b|^set system host-?name|^set host-?name|system\s+identity", "hostname", 1.0),

    # --- Privileged secret ---
    (r"^enable (secret|password)\b", "privileged_secret", 1.0),
    (r"privileged.secret|admin.password", "privileged_secret", 0.9),

    # --- Telnet ---
    (r"\btelnet\b", "telnet_enable", 1.0),

    # --- SSH ---
    (r"\bssh\b.*\bv(er(sion)?)?\.?\s*2\b|version[- ]?2", "ssh_v2", 1.0),
    (r"\bssh\b", "ssh_v2", 0.7),

    # --- HTTP / HTTPS ---
    (r"\bwww-ssl\b.*disabl.*(no|false)", "https_enable", 0.9),
    (r"\bwww-ssl\b", "https_enable", 0.7),
    (r"\bhttps?\b.*disabl", "http_disable", 1.0),
    (r"\bwww\b(?!-ssl)", "http_disable", 0.8),
    (r"\bhttp\b(?!s).*disabl", "http_disable", 1.0),
    (r"\bhttps?\b", "https_enable", 0.6),

    # --- Password security ---
    (r"encrypt.*password|password.*encrypt", "password_encryption", 1.0),
    (r"min(imum)?[-_ ]?length", "min_password_length", 1.0),
    (r"password[-_ ]?policy", "min_password_length", 0.8),

    # --- Banner ---
    (r"banner|motd|login[-_ ]?message|login[-_ ]?announcement", "banner", 0.9),

    # --- Session timeout ---
    (r"idle[-_ ]?timeout|exec[-_ ]?timeout|session[-_ ]?timeout|admintimeout|"
     r"console.*timeout|admin[-_ ]?session", "exec_timeout", 1.0),

    # --- Logging / syslog ---
    (r"syslog|logging\s+(host|trap|buffered|action|server)|log\s+syslog", "logging", 0.9),

    # --- NTP ---
    (r"\bntp\b|time.?sync|ntp-client|primary-ntp|clock\s+ntp", "ntp", 1.0),

    # --- AAA / RADIUS / TACACS ---
    (r"\baaa\b|\bradius\b|\btacacs\b|authentication-order|auth-profile|"
     r"aaa-profile|radius-enabled", "aaa", 0.9),

    # --- Management access / ACL ---
    (r"access-class|access-list|\bacl\b|trusthost|firewall\s+filter|"
     r"src-address|chain=input|firewall\s+filter\s+input|family\s+inet\s+filter", "vty_acl", 0.8),

    # --- SNMP ---
    (r"community.*\b(public|private)\b|snmp.*\bpublic\b|snmp.*\bprivate\b", "snmp_weak", 1.0),
    (r"snmp.*community|community\s+name", "snmp_strong", 0.7),
]

_NEGATIVE_TOKENS = ["disable", "disabled", "no ", "delete", "remove", "=no", "=off", "=false"]


def _is_negative(line: str) -> bool:
    return any(tok in line for tok in _NEGATIVE_TOKENS)


def suggest(raw_line, top_n=3):
    line = raw_line.strip().lower()

    if is_ignorable(raw_line):
        return []

    # Too short / generic to classify reliably
    if len(line.split()) < 2:
        return []

    negative = _is_negative(line)
    scores = {}

    for pattern, category, weight in _KEYWORD_RULES:
        if re.search(pattern, line):
            if category == "telnet_enable" and negative:
                category = "telnet_disable"
            scores[category] = scores.get(category, 0) + weight

    if not scores:
        return []

    max_score = max(scores.values())
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    results = []
    for category, score in ranked:
        if category not in CATEGORY_ACTIONS:
            continue
        # Tiered confidence: absolute score determines how certain we are,
        # not just relative to the best. Weak patterns get lower confidence.
        relative = score / max_score                    # 0..1
        absolute = min(1.0, score)                      # raw strength
        base = 55 + 40 * (0.6 * relative + 0.4 * absolute)
        confidence = max(55, min(96, int(base)))
        label = CATEGORY_ACTIONS[category][0]
        results.append((category, label, confidence))
    return results


def category_choices():
    choices = [("ignored", CATEGORY_ACTIONS["ignored"][0])]
    for key, (label, _fn) in CATEGORY_ACTIONS.items():
        if key == "ignored":
            continue
        choices.append((key, label))
    return choices