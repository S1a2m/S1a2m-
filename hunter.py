#!/usr/bin/env python3
"""Offline defensive review of explicitly approved local GitHub Actions files."""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib import parse
from zipfile import BadZipFile

import yaml

ROOT = Path(__file__).parent.resolve()
REPORTS = ROOT / "reports"
MAX_FILE_BYTES = 150_000

UNTRUSTED = re.compile(r"github\.event\.(?:(?:issue|pull_request|comment|review|discussion|review_comment)\.(?:title|body)|(?:head_commit|commits)\.|.*?\.body)", re.I)
PR_HEAD = re.compile(r"github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|head_ref)", re.I)
EXECUTION = re.compile(r"\b(?:npm\s+(?:ci|install|test)|pnpm\s+(?:install|test)|yarn\s+(?:install|test)|pip\s+install|pytest|python\s+\S+|bash\s+\S+|sh\s+\S+|make(?:\s|$)|go\s+test|cargo\s+(?:test|build)|mvn\s+test|gradle\s+\S+|\.\/\S+)\b", re.I)
ARTIFACT = re.compile(r"(?:download-artifact|gh\s+run\s+download|unzip\s+|tar\s+(?:-x|xf))", re.I)


def safe_repo_name(repo: str):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo)) and not repo.startswith(".")


def safe_filename(name: str):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}\.ya?ml", name))


def choose_repos(repos: list[str], count: int, day) -> list[str]:
    # Vary the selection daily; reproducible and no hidden preference for always scanning first entries.
    if not repos:
        return []
    start = (day.toordinal() * count) % len(repos)
    return [repos[(start + i) % len(repos)] for i in range(min(count, len(repos)))]


def workflow_findings(repo: str, workflow_file: str, source: str, branch: str, *, local: bool = False) -> list[dict]:
    try:
        doc = yaml.load(source, Loader=yaml.BaseLoader) or {}
    except yaml.YAMLError:
        if local:
            raise ValueError("invalid workflow YAML") from None
        return []
    if not isinstance(doc, dict):
        return []
    triggers = doc.get("on", {})
    if isinstance(triggers, str):
        event_set = {triggers}
    elif isinstance(triggers, list):
        event_set = {event for event in triggers if isinstance(event, str)}
    elif isinstance(triggers, dict):
        event_set = set(triggers.keys())
    else:
        event_set = set()
    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        return []
    findings = []
    lines = source.splitlines()

    def add(rule: str, severity: str, job: str, reason: str, anchor: str):
        line = next((idx for idx, value in enumerate(lines, 1) if anchor and anchor in value), 1)
        encoded = parse.quote(branch, safe="/")
        url = f"https://github.com/google/{repo}/blob/{encoded}/.github/workflows/{workflow_file}#L{line}"
        project = repo if local else f"google/{repo}"
        if local:
            url = f"{workflow_file}#L{line}"
        fingerprint = hashlib.sha256(f"{project}/{workflow_file}/{job}/{rule}".encode()).hexdigest()[:12]
        findings.append({"id": fingerprint, "project": project, "file": workflow_file,
                         "job": str(job), "line": line, "rule": rule, "priority": severity,
                         "reason": reason, "url": url, "validated": False})

    top_permission = doc.get("permissions")
    for jobname, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        perms = job.get("permissions", top_permission)
        write_access = perms == "write-all" or (isinstance(perms, dict) and any(
            str(v) == "write" for k, v in perms.items() if str(k) in ("contents", "actions", "packages", "id-token", "workflows")))
        if "pull_request_target" in event_set:
            checkout_pos = -1
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                if "actions/checkout@" in str(step.get("uses", "")):
                    opts = step.get("with", {}) or {}
                    if PR_HEAD.search(str(opts)):
                        checkout_pos = idx
            if checkout_pos >= 0:
                for step in steps[checkout_pos + 1:]:
                    if not isinstance(step, dict):
                        continue
                    run = str(step.get("run", ""))
                    if EXECUTION.search(run):
                        add("PRT_HEAD_EXECUTION_CANDIDATE", "high", jobname,
                            "pull_request_target + checkout of untrusted PR head, followed by a command which may execute repo content. Check job trust boundaries and effective permissions.", "pull_request_target")
                        break
            if write_access:
                add("PRT_WRITE_PERMISSION_REVIEW", "low", jobname,
                    "pull_request_target job appears to have write-capable permissions. Context-dependent; NOT a vulnerability by itself.", "pull_request_target")
        for step in steps:
            if not isinstance(step, dict):
                continue
            run = str(step.get("run", ""))
            if run and "${{" in run and UNTRUSTED.search(run):
                add("UNTRUSTED_EXPRESSION_IN_SHELL", "medium", jobname,
                    "Potential untrusted GitHub event value interpolated directly into shell run. Check quoting, reachability, and whether attacker-controlled input can be used.", "${{")
                break
        if "workflow_run" in event_set:
            script = "\n".join(str(s.get("run", "")) + "\n" + str(s.get("uses", ""))
                                for s in steps if isinstance(s, dict))
            if ARTIFACT.search(script) and EXECUTION.search(script) and write_access:
                add("WORKFLOW_RUN_ARTIFACT_REVIEW", "medium", jobname,
                    "workflow_run with write permissions and artifact processing/execution pattern. Manual data-flow inspection needed.", "workflow_run")
    return findings


def approved_workflows(checkout: Path, scope_file: Path):
    scope = json.loads(scope_file.read_text(encoding="utf-8-sig"))
    if not isinstance(scope, dict) or scope.get("activity") != "offline-workflow-review":
        raise ValueError("scope must explicitly allow offline-workflow-review")
    if scope.get("approved") is not True:
        raise ValueError("scope requires explicit human approval")
    rules = scope.get("rules_reference")
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("scope requires a rules or owner approval reference")
    checkout = checkout.resolve(strict=True)
    if not checkout.is_dir() or scope.get("checkout") != str(checkout):
        raise ValueError("scope checkout must equal the resolved local checkout path")
    files = scope.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("scope requires an explicit nonempty file list")
    resolved = {}
    for name in files:
        prefix = ".github/workflows/"
        if not isinstance(name, str) or not name.startswith(prefix) or not safe_filename(name[len(prefix):]):
            raise ValueError("scope files must be exact .github/workflows YAML paths")
        path = (checkout / name).resolve(strict=True)
        if path != checkout / name or not path.is_file():
            raise ValueError("workflow must be a regular file at its approved location")
        if path in resolved:
            raise ValueError("duplicate scope file")
        resolved[path] = name
    return resolved


def read_workflow(path: Path):
    with path.open("rb") as stream:
        content = stream.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("workflow exceeds the local file size limit")
    return content.decode("utf-8-sig")


def run(demo: bool, checkout: Path | None, scope_file: Path | None):
    if demo:
        project = "synthetic-demo"
        files = {ROOT / "examples" / "suspicious-workflow.yml": "examples/suspicious-workflow.yml"}
    else:
        if checkout is None or scope_file is None:
            raise ValueError("provide both --checkout and --scope, or run --demo")
        files = approved_workflows(checkout, scope_file)
        project = checkout.resolve().name

    findings = [
        finding
        for path, name in files.items()
        for finding in workflow_findings(project, name, read_workflow(path), "", local=True)
    ]
    lines = [
        f"# Offline workflow review ({date.today().isoformat()})",
        "",
        f"Mode: {'synthetic fixture' if demo else 'approved local files'}",
        f"Files reviewed: {len(files)}",
        f"Unverified flags: {len(findings)}",
        "",
        "## Coverage",
        "",
    ]
    lines.extend(f"- {name}" for name in files.values())
    lines.extend(["", "## Human triage", "",
                  "Review effective permissions, triggering conditions and trust boundaries. Record a remediation or dismissal after review.",
                  "Share only the minimum evidence needed and redact secrets and personal information.", ""])
    for finding in findings:
        evidence = f"{finding['file']}:{finding['line']}"
        lines.append(f"- {finding['id']} | {finding['rule']} | {evidence} | {finding['reason']}")
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "daily-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (REPORTS / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    print(f"Reviewed {len(files)} workflow file(s), found {len(findings)} unverified flag(s).")


def advisory_main(argv):
    from advisories import report

    parser = argparse.ArgumentParser(
        prog="hunter.py advisories", description="Review approved local or HTTPS software inventory."
    )
    parser.add_argument("--scope", required=True, type=Path)
    inventory = parser.add_mutually_exclusive_group(required=True)
    inventory.add_argument("--inventory", type=Path)
    inventory.add_argument("--inventory-url", help="Exact owner-approved HTTPS inventory endpoint")
    parser.add_argument("--osv", required=True, action="append", type=Path,
                        help="Local OSV ZIP snapshot or single-record JSON file (repeatable)")
    parser.add_argument("--year", type=int, default=2026)
    parser.add_argument("--kev", type=Path)
    parser.add_argument("--epss", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999")
    try:
        result = report(args.scope, args.inventory, args.osv, args.year, args.kev, args.epss,
                        inventory_url=args.inventory_url,
                        token=os.environ.get("HUNTER_INVENTORY_TOKEN") if args.inventory_url else None)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, BadZipFile) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


def main():
    if sys.argv[1:2] == ["advisories"]:
        advisory_main(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.epilog = "Run hunter.py advisories --help for offline advisory inventory review."
    parser.add_argument("--checkout", type=Path, help="Approved local checkout")
    parser.add_argument("--scope", type=Path, help="Human-approved local JSON scope")
    parser.add_argument("--demo", action="store_true", help="Review the bundled synthetic fixture offline")
    args = parser.parse_args()
    if args.demo and (args.checkout is not None or args.scope is not None):
        parser.error("--demo must be used alone")
    try:
        run(args.demo, args.checkout, args.scope)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
