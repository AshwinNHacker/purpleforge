import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from purpleforge.detector.engine import load_rules, run_detection
from purpleforge.simulator.techniques import simulate, simulate_all

RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "purpleforge", "detector", "rules"
)


def test_rules_load():
    rules = load_rules(RULES_DIR)
    assert len(rules) == 8
    ids = {r.technique_id for r in rules}
    assert "T1059.001" in ids
    assert "T1490" in ids


def test_powershell_detection_fires():
    rules = load_rules(RULES_DIR)
    event = simulate("T1059.001")
    findings = run_detection([event], rules)
    assert len(findings) == 1
    assert findings[0].rule.technique_id == "T1059.001"


def test_benign_event_does_not_fire():
    rules = load_rules(RULES_DIR)
    benign_event = {
        "event_id": "benign-1",
        "host": "WKS-001",
        "user": "alice",
        "process": "notepad.exe",
        "command_line": "notepad.exe report.txt",
    }
    findings = run_detection([benign_event], rules)
    assert len(findings) == 0


def test_full_simulation_set_has_full_coverage():
    """Every bundled simulator should be caught by its matching rule —
    if this fails, either a simulator or its rule has drifted."""
    rules = load_rules(RULES_DIR)
    events = simulate_all()
    findings = run_detection(events, rules)
    detected_techniques = {f.rule.technique_id for f in findings}
    simulated_techniques = {e["technique_id"] for e in events}
    assert detected_techniques == simulated_techniques
