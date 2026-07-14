"""
Static metadata for the MITRE ATT&CK techniques this toolkit knows
how to simulate and detect. Keeping this separate from the simulator
and detector logic means adding a new technique is a three-step
process: add the metadata here, add a simulator function, add a
detection rule.
"""

TECHNIQUES = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols (C2 beacon)",
        "tactic": "Command and Control",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
    },
}


def describe(technique_id: str) -> dict:
    if technique_id not in TECHNIQUES:
        raise KeyError(f"Unknown technique id: {technique_id}")
    return TECHNIQUES[technique_id]
