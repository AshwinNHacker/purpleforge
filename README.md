# PurpleForge

![CI](https://github.com/<your-username>/purpleforge/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)

**A MITRE ATT&CK detection-validation framework** — generate synthetic
attack telemetry, run it through a detection-rule engine, and get a
Markdown coverage report showing exactly which techniques your rules
catch and which ones are gaps.

Built for purple-team work: it closes the loop between red team
technique coverage and blue team detection engineering, without
running a single live exploit.

```
 SIMULATE  ─────▶  DETECT  ─────▶  REPORT
 (synthetic          (rule            (coverage %,
  telemetry)          engine)          gaps, findings)
```

## Why this exists

Most "is our SOC ready?" conversations happen in a spreadsheet, months
after the last red-team engagement. PurpleForge makes that feedback
loop something you can run in five seconds, on a laptop, with no
target environment required — every technique is represented as
synthetic, SIEM-shaped log data (Sysmon-style process events, proxy
logs, Windows security events), never as an actual exploit or live
attack action.

## Features

- 🎯 **8 MITRE ATT&CK techniques** simulated out of the box, spanning
  Execution, Credential Access, C2, Persistence, Lateral Movement,
  Defense Evasion, and Impact
- 🔍 **Sigma-inspired YAML detection rules** — readable, easy to add
  to, no query language to learn
- 📊 **Markdown coverage reports** — technique-by-technique pass/fail,
  ready to paste into a ticket or a slide
- 🧩 **Pluggable** — add a new technique in three steps: metadata,
  simulator function, rule file (see `docs/ARCHITECTURE.md`)
- ✅ **Tested** — `pytest` suite that also acts as a regression check
  when you tune a rule and it accidentally stops firing

## Quickstart

```bash
git clone https://github.com/<your-username>/purpleforge.git
cd purpleforge
pip install -r requirements.txt

# One-shot: simulate every technique, run detections, write a report
python -m purpleforge.cli run --all --out-dir ./out
cat ./out/report.md
```

Or step through the pipeline manually:

```bash
python -m purpleforge.cli list-techniques
python -m purpleforge.cli simulate --all --out logs.json
python -m purpleforge.cli detect --input logs.json --out findings.json
python -m purpleforge.cli report --input logs.json --findings findings.json --out report.md
```

Simulate a single technique:

```bash
python -m purpleforge.cli simulate --technique T1003.001 --out lsass.json
```

## Example output

```
| Technique | Name                                | Tactic            | Simulated | Detected | Rule                               |
|-----------|--------------------------------------|--------------------|-----------|----------|-------------------------------------|
| T1059.001 | Command and Scripting Interpreter... | Execution          | ✅        | ✅       | Encoded / Hidden PowerShell Exec... |
| T1490     | Inhibit System Recovery              | Impact             | ✅        | ✅       | Shadow Copy Deletion via vssadmin   |
```

## Adding a technique

1. Add metadata to `purpleforge/simulator/mitre_map.py`
2. Add a `sim_<technique>()` function to `purpleforge/simulator/techniques.py`
   that returns a synthetic, SIEM-shaped event
3. Add a matching rule YAML file to `purpleforge/detector/rules/`

Full write-up in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Scope and intent

Everything this tool produces is **synthetic telemetry** — Python
dicts shaped like log lines. It does not execute commands, touch
memory, modify the registry, or make network connections. It's a
detection-engineering and reporting tool, not an attack tool, and is
intended for validating your own detections in your own lab or CI
pipeline.

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE).
