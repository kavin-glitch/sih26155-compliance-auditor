"""
Fallback parser used when vendor_detector cannot fingerprint the config.
Every non-empty line is checked against previously LEARNED mappings first.
Anything still unrecognized is surfaced to the admin via the training loop.
"""

from models.schema import default_normalized_dict, apply_category, is_ignorable
from ai import mapping_store

VENDOR = "unknown"


def parse(config_text: str, vendor_label: str = "unknown"):
    normalized = default_normalized_dict()
    evidence = {}
    unmatched = []
    learned = mapping_store.get_vendor_mappings(vendor_label)

    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if is_ignorable(line):
            continue

        category = mapping_store.match(vendor_label, raw, learned)
        if category:
            apply_category(normalized, evidence, category, raw)
        else:
            unmatched.append(raw)

    return normalized, evidence, unmatched