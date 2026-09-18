#!/usr/bin/env python3
"""Regenerate standards rows across fixture clones from CANONICAL_STANDARDS.

Single source of truth for the fixture sweep (grilling Q4/DRY): the CWE →
standards mapping lives once in tests/grader.py (CANONICAL_STANDARDS). This
script rewrites the `standards:` block in every findings/*.md clone, the
semicolon-joined `properties.standards` in exports/findings.sarif, and the
`standards` lists in traceability.json — it is the only place allowed to edit
fixture standards.

The negative fixture neg-g1.6 is deliberately excluded: it is the sole place
in the repo carrying an invalid standard ID (OWASP-ASVS V1) plus an inverted
priority order, so the generator must never "fix" it.

Usage:
    python3 tests/sync_standards.py          # dry run (print what would change)
    python3 tests/sync_standards.py --write  # apply the sweep
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from grader import CANONICAL_STANDARDS, parse_frontmatter  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SKIP = {"neg-g1.6", "neg-g1.6b"}


def _emit_standards(rows):
    lines = ["standards:"]
    for framework, requirement_id in rows:
        lines.append(f"  - framework: {framework}")
        lines.append(f"    requirement_id: {requirement_id}")
    return "\n".join(lines)


def _rewrite_md(path, rows, write):
    with open(path) as fh:
        text = fh.read()
    out = []
    replaced = False
    swallow = False
    for line in text.split("\n"):
        if line == "standards:":
            out.append(_emit_standards(rows))
            replaced = True
            swallow = True
            continue
        if swallow:
            if line.startswith(" "):  # indented rows of the old list
                continue
            swallow = False
        out.append(line)
    new_text = "\n".join(out)
    if replaced and new_text != text:
        if write:
            with open(path, "w") as fh:
                fh.write(new_text)
        return True
    return False


def _rewrite_sarif(path, write):
    raw = open(path).read()
    data = json.loads(raw)
    runs = data.get("runs") or []
    if not runs:
        return 0
    repl = []
    n = 0
    for result in runs[0].get("results", []):
        rows = CANONICAL_STANDARDS.get(result.get("ruleId", ""))
        if rows is None:
            continue
        old = (result.get("properties") or {}).get("standards")
        expected = "; ".join(f"{fw}:{rid}" for fw, rid in rows)
        if old == expected:
            continue
        n += 1
        pair = (json.dumps(old), json.dumps(expected))
        if pair not in repl:
            repl.append(pair)
    if not n:
        return 0
    if all(raw.count(old) for old, new in repl):
        for old, new in repl:
            raw = raw.replace(old, new)
        if write:
            with open(path, "w") as fh:
                fh.write(raw)
        return n
    for result in runs[0].get("results", []):
        rows = CANONICAL_STANDARDS.get(result.get("ruleId", ""))
        if rows is None:
            continue
        props = result.setdefault("properties", {})
        props["standards"] = "; ".join(f"{fw}:{rid}" for fw, rid in rows)
    if write:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
    return n


def _rewrite_traceability(path, id_by_cwe_id, write):
    raw = open(path).read()
    data = json.loads(raw)
    repl = []
    n = 0
    for fid, entry in (data.get("findings") or {}).items():
        cwe = id_by_cwe_id.get(fid)
        if cwe is None:
            continue
        rows = CANONICAL_STANDARDS.get(cwe)
        if rows is None:
            continue
        old = entry.get("standards")
        expected = [f"{fw}:{rid}" for fw, rid in rows]
        if old == expected:
            continue
        n += 1
        pair = (json.dumps(old), json.dumps(expected))
        if pair not in repl:
            repl.append(pair)
    if not n:
        return 0
    if all(raw.count(old) for old, new in repl):
        for old, new in repl:
            raw = raw.replace(old, new)
        if write:
            with open(path, "w") as fh:
                fh.write(raw)
        return n
    for fid, entry in (data.get("findings") or {}).items():
        cwe = id_by_cwe_id.get(fid)
        if cwe is None:
            continue
        rows = CANONICAL_STANDARDS.get(cwe)
        if rows is None:
            continue
        entry["standards"] = [f"{fw}:{rid}" for fw, rid in rows]
    if write:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
    return n


def _fixture_roots():
    for dirpath, dirs, files in os.walk(FIXTURES_DIR):
        if os.path.basename(dirpath) == ".red-team":
            root = os.path.dirname(dirpath)
            if os.path.basename(root) in SKIP:
                continue
            yield root


def _iter_finding_paths(root):
    findings_dir = os.path.join(root, ".red-team", "findings")
    if not os.path.isdir(findings_dir):
        return
    for name in sorted(os.listdir(findings_dir)):
        if name.endswith(".md") and name != "index.md":
            yield os.path.join(findings_dir, name)


def _iter_md_findings(root):
    """Yield (path, cwe, fid) for every finding md with a parseable cwe."""
    for path in _iter_finding_paths(root):
        fm = parse_frontmatter(open(path).read())
        if fm and fm.get("cwe"):
            yield path, fm["cwe"], fm.get("id")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="apply changes (default: dry run)")
    args = ap.parse_args()

    mode = "write" if args.write else "dry-run"
    files_changed = 0
    rows_changed = 0
    print(f"== sync_standards.py ({mode}) — sweeping {len(list(_fixture_roots()))} fixtures ==")

    for root in _fixture_roots():
        id_by_cwe_id = {}
        for path, cwe, fid in _iter_md_findings(root):
            if fid:
                id_by_cwe_id[fid] = cwe
        for path, cwe, fid in _iter_md_findings(root):
            rows = CANONICAL_STANDARDS.get(cwe)
            if rows is None:
                continue
            rel = os.path.relpath(path, FIXTURES_DIR)
            n = _rewrite_md(path, rows, args.write)
            if n:
                files_changed += 1
                rows_changed += 1
                print(f"  {mode.upper()}  {rel}")
        sarif = os.path.join(root, ".red-team", "exports", "findings.sarif")
        if os.path.isfile(sarif):
            n = _rewrite_sarif(sarif, args.write)
            if n:
                files_changed += 1
                rows_changed += n
                print(f"  {mode.upper()}  {os.path.relpath(sarif, FIXTURES_DIR)}")
        trace = os.path.join(root, ".red-team", "traceability.json")
        if os.path.isfile(trace):
            n = _rewrite_traceability(trace, id_by_cwe_id, args.write)
            if n:
                files_changed += 1
                rows_changed += n
                print(f"  {mode.upper()}  {os.path.relpath(trace, FIXTURES_DIR)}")

    print(f"== {files_changed} files, {rows_changed} rows {'changed' if args.write else 'would change'} ==")


if __name__ == "__main__":
    main()