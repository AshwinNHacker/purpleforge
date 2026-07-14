# Sample Run

```bash
$ python -m purpleforge.cli list-techniques
T1059.001    Execution            Command and Scripting Interpreter: PowerShell
T1003.001    Credential Access    OS Credential Dumping: LSASS Memory
T1071.001    Command and Control  Application Layer Protocol: Web Protocols (C2 beacon)
T1547.001    Persistence          Boot or Logon Autostart Execution: Registry Run Keys
T1021.001    Lateral Movement     Remote Services: Remote Desktop Protocol
T1055        Defense Evasion      Process Injection
T1027        Defense Evasion      Obfuscated Files or Information
T1490        Impact               Inhibit System Recovery

$ python -m purpleforge.cli run --all --out-dir ./out
[INFO] purpleforge: Simulated 8 technique(s), 8 detection(s).
[INFO] purpleforge: Report: ./out/report.md
```

`./out/report.md` (excerpt):

```
# PurpleForge Detection Coverage Report

- Techniques simulated: 8
- Techniques detected: 8
- Coverage: 100.0%

## Technique Coverage

| Technique | Name | Tactic | Simulated | Detected | Rule |
|---|---|---|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | ✅ | ✅ | Suspicious Access to LSASS Memory |
| T1490 | Inhibit System Recovery | Impact | ✅ | ✅ | Shadow Copy Deletion via vssadmin |
```

## Pointing it at real data

`detect` just needs a JSON list of flat dicts. If your EDR/SIEM can
export alerts or raw events as JSON with the field names used in
`purpleforge/detector/rules/*.yml` (or you write new rules matching
your own schema), you can run:

```bash
python -m purpleforge.cli detect --input your_export.json --out findings.json
python -m purpleforge.cli report --input your_export.json --findings findings.json --out report.md
```
