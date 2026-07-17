# Contributing

PRs adding new ATT&CK technique coverage are the easiest way to
contribute — see `docs/ARCHITECTURE.md` for the three-step pattern
(metadata → simulator → rule).

## Local setup

```bash
git clone https://github.com/<your-username>/purpleforge.git
cd purpleforge
pip install -r requirements.txt
pip install pytest
pytest tests/ -v
```

## Guidelines

- Every new technique needs: an entry in `simulator/mitre_map.py`, a
  `sim_*` function in `simulator/techniques.py`, and a rule file in
  `detector/rules/`.
- Simulators must only build and return plain dicts — no shelling
  out, no filesystem/registry writes, no network calls. The point of
  this project is safe-to-run detection validation, not attack
  tooling.
- Run `pytest tests/` before opening a PR — `test_full_simulation_set_has_full_coverage`
  will catch a simulator/rule mismatch.
- Keep rule files readable top-to-bottom; if a detection needs OR
  logic, split it into two rule files rather than extending the DSL.
