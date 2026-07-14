"""
Telemetry simulators.

Each function returns a synthetic log record shaped like the kind of
event a SIEM / EDR would already be collecting (Sysmon-style process
creation, Windows Security event, or proxy/DNS log). Nothing here
executes a command, touches memory, writes to the registry, or
contacts a network. These are plain Python dicts built to *look like*
the telemetry a real technique would produce, so the detector module
has something realistic to test rules against.

This is the same idea used by tools like Atomic Red Team's "telemetry
only" mode or Splunk's attack_range synthetic datasets — safe to run
anywhere, useful for validating that your detections actually match.
"""

import random
import uuid
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _base_event(host, user, technique_id):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now(),
        "host": host,
        "user": user,
        "technique_id": technique_id,
    }


def sim_T1059_001_powershell(host="WKS-014", user="jsmith"):
    """Encoded PowerShell launch — classic execution telemetry."""
    event = _base_event(host, user, "T1059.001")
    event.update({
        "log_source": "sysmon:1",
        "process": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
        "integrity_level": "High",
    })
    return event


def sim_T1003_001_lsass_dump(host="WKS-014", user="jsmith"):
    """A process opening a handle to LSASS with dump-capable access rights."""
    event = _base_event(host, user, "T1003.001")
    event.update({
        "log_source": "sysmon:10",
        "process": "rundll32.exe",
        "target_process": "lsass.exe",
        "granted_access": "0x1010",
        "call_trace": "C:\\Windows\\System32\\dbghelp.dll+0x2f10",
    })
    return event


def sim_T1071_001_c2_beacon(host="WKS-014", user="jsmith"):
    """Periodic low-and-slow HTTPS beacon to an unclassified domain."""
    event = _base_event(host, user, "T1071.001")
    event.update({
        "log_source": "proxy",
        "process": "rundll32.exe",
        "dest_domain": f"cdn-{random.randint(1000,9999)}-update.net",
        "dest_port": 443,
        "bytes_out": random.randint(200, 600),
        "interval_seconds": 60,
        "user_agent": "Microsoft-CryptoAPI/10.0",
    })
    return event


def sim_T1547_001_run_key(host="WKS-014", user="jsmith"):
    """Persistence via a HKCU Run key pointing at a temp-folder binary."""
    event = _base_event(host, user, "T1547.001")
    event.update({
        "log_source": "sysmon:13",
        "process": "reg.exe",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "registry_value": "UpdaterSvc",
        "registry_data": r"C:\Users\jsmith\AppData\Local\Temp\upd.exe",
    })
    return event


def sim_T1021_001_rdp(host="SRV-DC01", user="svc_backup"):
    """Interactive RDP logon to a server from an unusual source host."""
    event = _base_event(host, user, "T1021.001")
    event.update({
        "log_source": "winevent:4624",
        "logon_type": 10,
        "source_host": "WKS-014",
        "auth_package": "NTLM",
    })
    return event


def sim_T1055_process_injection(host="WKS-014", user="jsmith"):
    """CreateRemoteThread into a signed, unrelated process."""
    event = _base_event(host, user, "T1055")
    event.update({
        "log_source": "sysmon:8",
        "source_process": "winword.exe",
        "target_process": "explorer.exe",
        "start_address": "0x7ffcbf220000",
        "newthread": True,
    })
    return event


def sim_T1027_obfuscation(host="WKS-014", user="jsmith"):
    """A dropped file with a base64/gzip payload signature."""
    event = _base_event(host, user, "T1027")
    event.update({
        "log_source": "edr:file_write",
        "process": "powershell.exe",
        "file_path": r"C:\Users\jsmith\AppData\Local\Temp\svc_helper.ps1",
        "entropy": 7.8,
        "contains_base64_blob": True,
    })
    return event


def sim_T1490_inhibit_recovery(host="SRV-FILE01", user="jsmith")   :
    """Shadow-copy deletion — common ransomware pre-impact step."""
    event = _base_event(host, user, "T1490")
    event.update({
        "log_source": "sysmon:1",
        "process": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "parent_process": "cmd.exe",
    })
    return event


SIMULATORS = {
    "T1059.001": sim_T1059_001_powershell,
    "T1003.001": sim_T1003_001_lsass_dump,
    "T1071.001": sim_T1071_001_c2_beacon,
    "T1547.001": sim_T1547_001_run_key,
    "T1021.001": sim_T1021_001_rdp,
    "T1055": sim_T1055_process_injection,
    "T1027": sim_T1027_obfuscation,
    "T1490": sim_T1490_inhibit_recovery,
}


def simulate(technique_id: str) -> dict:
    if technique_id not in SIMULATORS:
        raise KeyError(f"No simulator registered for {technique_id}")
    return SIMULATORS[technique_id]()


def simulate_all() -> list:
    return [fn() for fn in SIMULATORS.values()]
