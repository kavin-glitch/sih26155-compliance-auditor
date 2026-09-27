RISK_CONTEXT = {
    "CIS-01": {
        "why": "Telnet transmits credentials and session data in cleartext. Anyone on the network path can capture an admin password with a passive sniffer.",
        "attack_path": [
            "Telnet service exposed on management interface",
            "Attacker sniffs management VLAN traffic",
            "Admin credentials captured in cleartext",
            "Attacker authenticates as administrator",
            "Full device configuration control obtained",
        ],
    },
    "CIS-02": {
        "why": "SSHv1 has known cryptographic weaknesses. Only SSHv2 should be permitted.",
        "attack_path": [
            "SSHv1 supported on management interface",
            "Attacker performs protocol downgrade or MITM",
            "Session keys compromised",
            "Encrypted admin session decrypted",
            "Unauthorized administrative access",
        ],
    },
    "CIS-03": {
        "why": "HTTP management sends credentials unencrypted. Any device on the management path can capture them.",
        "attack_path": [
            "HTTP management enabled",
            "Admin logs in via web UI",
            "Credentials transmitted in cleartext",
            "Session cookie hijacked",
            "Attacker inherits admin session",
        ],
    },
    "CIS-04": {
        "why": "Without HTTPS, administrators have no secure alternative to HTTP.",
        "attack_path": ["No encrypted web management", "Admins fall back to HTTP or Telnet", "Credentials exposed", "Device compromise"],
    },
    "CIS-05": {
        "why": "Unencrypted passwords stored in the config file can be read by anyone with read access to the config.",
        "attack_path": ["Config with plaintext password leaked", "Attacker reads local password hashes", "Password reused on other systems", "Lateral movement"],
    },
    "CIS-06": {
        "why": "Short passwords are vulnerable to brute-force and dictionary attacks.",
        "attack_path": ["Weak password policy", "Remote brute-force attempt", "Account compromised", "Device configuration manipulated"],
    },
    "CIS-07": {
        "why": "A login banner provides legal notice and discourages unauthorized access.",
        "attack_path": ["No legal warning on login", "Unauthorized access harder to prosecute", "Reduced deterrence"],
    },
    "CIS-08": {
        "why": "Idle sessions left open can be hijacked by someone with brief access to an unattended terminal.",
        "attack_path": ["Admin leaves session unattended", "Session remains active", "Attacker uses live session", "Configuration changes made as admin"],
    },
    "CIS-09": {
        "why": "Without centralized logging, administrative actions and security events are invisible.",
        "attack_path": ["No syslog destination configured", "Attacker actions leave no external trace", "Local logs cleared by attacker", "Incident response impossible"],
    },
    "CIS-10": {
        "why": "Without NTP, log timestamps drift. Cross-device correlation becomes unreliable.",
        "attack_path": ["Device clock drifts", "Log timestamps inconsistent", "Attack timeline reconstruction fails", "Forensic investigation compromised"],
    },
    "CIS-11": {
        "why": "Local-only authentication means no central revocation and no consistent policy.",
        "attack_path": ["Local-only authentication", "Employee leaves, credentials remain valid", "No central revocation", "Ex-employee retains access"],
    },
    "CIS-12": {
        "why": "Management interfaces open to any source address are reachable from anywhere on the network.",
        "attack_path": ["No ACL restricting management sources", "Attacker reaches management port", "Credential attack / exploit", "Device compromised from inside"],
    },
    "CIS-13": {
        "why": "Default SNMP community strings ('public'/'private') are known to every attacker.",
        "attack_path": ["Default SNMP community in use", "Attacker scans with default strings", "Full device inventory disclosed", "Targeted exploitation"],
    },
    "CIS-14": {
        "why": "Without lockout, an attacker can try unlimited passwords without triggering a defensive response.",
        "attack_path": ["No lockout policy", "Unlimited login attempts", "Brute-force succeeds", "Admin account compromised"],
    },
    "NIST-AC-17": {"why": "NIST SP 800-53 AC-17 requires encryption for all remote access.", "attack_path": ["Remote access unencrypted", "Session intercepted", "Admin compromise"]},
    "NIST-CM-7":  {"why": "NIST CM-7: least functionality - Telnet must be disabled.", "attack_path": ["Telnet enabled", "Sniffing yields credentials", "Unauthorized access"]},
    "NIST-SC-8":  {"why": "NIST SC-8: transmission confidentiality - HTTP is unencrypted.", "attack_path": ["HTTP management enabled", "Credentials exposed", "Session hijack"]},
    "NIST-SC-8b": {"why": "NIST SC-8: encrypted management must be available.", "attack_path": ["No HTTPS available", "Admins use insecure alternatives", "Credential exposure"]},
    "NIST-IA-5":  {"why": "NIST IA-5: minimum password complexity required.", "attack_path": ["Weak password policy", "Brute-force succeeds", "Account compromise"]},
    "NIST-IA-5b": {"why": "NIST IA-5: stored authenticators must be protected.", "attack_path": ["Plaintext passwords in config", "Config leak", "Credential exposure"]},
    "NIST-AC-11": {"why": "NIST AC-11: sessions must lock after inactivity.", "attack_path": ["Idle session persists", "Session hijack", "Unauthorized changes"]},
    "NIST-AU-2":  {"why": "NIST AU-2: audit events must be generated and retained.", "attack_path": ["No audit trail", "Attack goes undetected", "No forensic evidence"]},
    "NIST-AU-8":  {"why": "NIST AU-8: reliable timestamps require time sync.", "attack_path": ["Clock drift", "Log correlation fails", "Forensics compromised"]},
    "NIST-AC-7":  {"why": "NIST AC-7: limit unsuccessful login attempts.", "attack_path": ["Unlimited attempts", "Brute-force succeeds", "Account compromised"]},
    "NIST-SI-4":  {"why": "NIST SI-4: monitoring must not use default credentials.", "attack_path": ["Default SNMP string", "Reconnaissance succeeds", "Targeted exploitation"]},
    "NIST-AC-4":  {"why": "NIST AC-4: management access must be restricted.", "attack_path": ["Management port exposed", "Reachable from attacker segment", "Compromise"]},
    "NIST-IA-2":  {"why": "NIST IA-2: centralized identification and authentication.", "attack_path": ["Local-only auth", "No central revocation", "Stale credentials persist"]},
    "NIST-AC-8":  {"why": "NIST AC-8: system use notification before access.", "attack_path": ["No warning banner", "Weakened deterrence", "Legal standing reduced"]},
}


def get_risk(rule_id):
    return RISK_CONTEXT.get(rule_id, {
        "why": "This control should be hardened per the selected security framework.",
        "attack_path": ["Control not satisfied", "Increased attack surface", "Potential compromise"],
    })