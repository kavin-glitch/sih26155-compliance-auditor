"""
Vendor fingerprinting: looks at a handful of unmistakable syntax markers to
guess which vendor produced a config file, before picking the right parser.
Unrecognized syntax correctly falls through to 'unknown', which routes into
the generic/AI-training parser instead of crashing.
"""

_SIGNATURES = [
    ("cisco", ["line vty", "ip ssh version", "enable secret", "service password-encryption"]),
    ("fortinet", ["config system global", "config system interface", "set allowaccess", "config firewall"]),
    ("juniper", ["set system services", "set system login", "set interfaces", "set firewall filter"]),
]


def detect(config_text: str) -> str:
    text = config_text.lower()
    scores = {vendor: 0 for vendor, _ in _SIGNATURES}
    for vendor, markers in _SIGNATURES:
        for marker in markers:
            if marker in text:
                scores[vendor] += 1
    best_vendor, best_score = max(scores.items(), key=lambda kv: kv[1])
    if best_score == 0:
        return "unknown"
    return best_vendor
