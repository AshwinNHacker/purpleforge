"""
Command-line entrypoint.

    purpleforge simulate --all --out logs.json
    purpleforge simulate --technique T1059.001 --out logs.json
    purpleforge detect --input logs.json --out findings.json
    purpleforge report --input logs.json --findings findings.json --out report.md
    purpleforge run --all --out-dir ./out          # full pipeline, one shot
    purpleforge list-techniques
"""

import argparse
import json
import os
import sys

from purpleforge.detector.engine import load_rules, run_detection, Finding, Rule
from purpleforge.reporting.report_generator import build_report
from purpleforge.simulator.mitre_map import TECHNIQUES
from purpleforge.simulator.techniques import simulate, simulate_all
from purpleforge.utils.logger import get_logger

log = get_logger()

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "detector", "rules")


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _findings_to_json(findings):
    return [
        {
            "rule_id": f.rule.id,
            "title": f.rule.title,
            "technique_id": f.rule.technique_id,
            "level": f.rule.level,
            "event_id": f.event.get("event_id"),
            "host": f.event.get("host"),
            "user": f.event.get("user"),
        }
        for f in findings
    ]


def cmd_list_techniques(args):
    for tid, meta in TECHNIQUES.items():
        print(f"{tid:12} {meta['tactic']:20} {meta['name']}")


def cmd_simulate(args):
    if args.all:
        events = simulate_all()
    elif args.technique:
        events = [simulate(args.technique)]
    else:
        log.error("Pass --all or --technique <ATT&CK ID>")
        sys.exit(1)
    _write_json(args.out, events)
    log.info(f"Wrote {len(events)} synthetic event(s) to {args.out}")


def cmd_detect(args):
    events = _read_json(args.input)
    rules = load_rules(args.rules_dir)
    findings = run_detection(events, rules)
    _write_json(args.out, _findings_to_json(findings))
    log.info(f"{len(findings)} finding(s) from {len(rules)} rule(s) against {len(events)} event(s) -> {args.out}")


def cmd_report(args):
    events = _read_json(args.input)
    raw_findings = _read_json(args.findings)
    rules_by_id = {r.id: r for r in load_rules(args.rules_dir)}

    findings = []
    for rf in raw_findings:
        rule = rules_by_id[rf["rule_id"]]
        event = next((e for e in events if e.get("event_id") == rf["event_id"]), {})
        findings.append(Finding(rule=rule, event=event))

    report = build_report(events, findings)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report)
    log.info(f"Report written to {args.out}")


def cmd_run(args):
    os.makedirs(args.out_dir, exist_ok=True)
    events = simulate_all() if args.all else [simulate(t) for t in args.technique]
    rules = load_rules(args.rules_dir)
    findings = run_detection(events, rules)

    _write_json(os.path.join(args.out_dir, "events.json"), events)
    _write_json(os.path.join(args.out_dir, "findings.json"), _findings_to_json(findings))
    report_path = os.path.join(args.out_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(build_report(events, findings))

    log.info(f"Simulated {len(events)} technique(s), {len(findings)} detection(s).")
    log.info(f"Report: {report_path}")


def main():
    parser = argparse.ArgumentParser(prog="purpleforge", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list-techniques", help="List supported ATT&CK techniques")
    p_list.set_defaults(func=cmd_list_techniques)

    p_sim = sub.add_parser("simulate", help="Generate synthetic telemetry")
    p_sim.add_argument("--technique", help="ATT&CK technique id, e.g. T1059.001")
    p_sim.add_argument("--all", action="store_true", help="Simulate every known technique")
    p_sim.add_argument("--out", default="logs.json")
    p_sim.set_defaults(func=cmd_simulate)

    p_det = sub.add_parser("detect", help="Run detection rules against telemetry")
    p_det.add_argument("--input", required=True)
    p_det.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p_det.add_argument("--out", default="findings.json")
    p_det.set_defaults(func=cmd_detect)

    p_rep = sub.add_parser("report", help="Build a Markdown coverage report")
    p_rep.add_argument("--input", required=True, help="events.json from simulate")
    p_rep.add_argument("--findings", required=True, help="findings.json from detect")
    p_rep.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p_rep.add_argument("--out", default="report.md")
    p_rep.set_defaults(func=cmd_report)

    p_run = sub.add_parser("run", help="Full pipeline: simulate -> detect -> report")
    p_run.add_argument("--all", action="store_true")
    p_run.add_argument("--technique", nargs="*", default=[])
    p_run.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p_run.add_argument("--out-dir", default="./purpleforge-out")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
