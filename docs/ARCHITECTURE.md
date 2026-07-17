# Architecture

## Pipeline

```
simulator/techniques.py  →  events (list[dict])
                                   │
                                   ▼
detector/rules/*.yml     →  detector/engine.py  →  findings (list[Finding])
                                   │
                                   ▼
                       reporting/report_generator.py
                                   │
                                   ▼
                              report.md
```

## Modules

- **`simulator/`** — Produces synthetic telemetry. `mitre_map.py`
  holds static ATT&CK metadata (name, tactic) per technique ID.
  `techniques.py` holds one `sim_*` function per technique, each
  returning a dict shaped like real SIEM/EDR output. Nothing in this
  module executes code, touches the filesystem/registry, or opens a
  network connection — it only builds Python dicts.

- **`detector/`** — `engine.py` loads YAML rule files and evaluates
  them against events. Rules use a flat, Sigma-inspired shorthand:
  a detection key is `<field>_<operator>`, e.g. `command_line_contains_any`.
  A key with no operator suffix means exact match. All conditions in
  a rule are AND-ed. This is intentionally simpler than full Sigma —
  no nested boolean logic — because the goal is a rule file you can
  read top to bottom in ten seconds, not a general-purpose query
  language. If you need OR/nested logic, split into multiple rule
  files; they're cheap.

- **`reporting/`** — Takes the raw events + findings and renders a
  Markdown report: overall coverage %, a per-technique table, an
  explicit "gaps" section, and a findings appendix.

- **`cli.py`** — Thin argparse wrapper tying the three stages
  together, plus a `run` subcommand that does all three in one call.

## Adding a new technique — worked example

Say you want to add **T1218.011 (Signed Binary Proxy Execution:
Rundll32)**.

1. **Metadata** — in `mitre_map.py`:
   ```python
   "T1218.011": {"name": "Signed Binary Proxy Execution: Rundll32", "tactic": "Defense Evasion"},
   ```

2. **Simulator** — in `techniques.py`:
   ```python
   def sim_T1218_011_rundll32(host="WKS-014", user="jsmith"):
       event = _base_event(host, user, "T1218.011")
       event.update({
           "log_source": "sysmon:1",
           "process": "rundll32.exe",
           "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"",
       })
       return event
   ```
   Register it in the `SIMULATORS` dict.

3. **Rule** — `detector/rules/t1218_011_rundll32.yml`:
   ```yaml
   id: rule-t1218-011
   title: Rundll32 JavaScript Proxy Execution
   technique_id: T1218.011
   level: high
   log_source: sysmon:1
   detection:
     process: rundll32.exe
     command_line_contains_any:
       - "javascript:"
   description: Flags rundll32 being used to proxy-execute inline JavaScript.
   ```

4. Run `pytest tests/` — `test_full_simulation_set_has_full_coverage`
   will fail loudly if the simulator and rule don't agree, which is
   exactly the kind of drift this test exists to catch.

## Design decisions worth knowing

- **Synthetic telemetry, not live execution.** The simulators never
  run a real command or touch the OS. This keeps the tool safe to run
  anywhere (a laptop, CI, a shared demo box) and keeps the repo's
  purpose unambiguous: detection engineering and reporting, not
  attack tooling.
- **Flat rule DSL over a full query language.** Easier to read, easier
  to review in a PR, easier to explain to someone who isn't a Sigma
  expert. The tradeoff is no boolean nesting — acceptable for this
  scope.
- **JSON as the interchange format between stages.** `simulate`,
  `detect`, and `report` can be run independently and piped through
  files, which makes it easy to swap in a real event source (export
  your EDR's alerts as the same JSON shape and point `detect` at it).
