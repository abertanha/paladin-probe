#!/usr/bin/env python3
"""Paladin-probe grader — self-audit compliance checker.

Usage:
    python3 tests/grader.py /path/to/project-root
    python3 tests/grader.py /path/to/project-root --json   # machine-readable report
    python3 tests/grader.py /path/to/project-root --verbose # include PASS lines

Checks a .red-team/ directory against the skill contracts and exports a JSON
report with PASS/FAIL/WARN per check. Exit code 0 → all passed; 1 → failures.
"""

import re
import sys
import json
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# ── Config ───────────────────────────────────────────────────────────────

SKILL_DIR = Path(__file__).resolve().parent.parent
REF_DIR = SKILL_DIR / "references"

SCHEMA_VERSION_REQUIRED = 2

# Canonical probe-category vocabulary. Single source of truth is the
# "Probe Categories" section of SKILL.md — if a heading changes there,
# change it here in the same commit.
CANONICAL_CATEGORIES = {
    "Authentication Abuse", "Authorization Abuse", "Business Logic",
    "Input Validation", "SSRF", "Insecure Deserialization",
    "Secrets Exposure", "Resource Exhaustion", "Config Hardening",
    "Dependency Audit",
}

# Valid skeptic_review values (flat frontmatter key; see references/skeptic-review.md)
SKEPTIC_VERDICTS = {"upheld", "weakened", "killed", "skipped-no-harness"}

CLOSED_VOCAB = {"CWE", "OWASP-Top-2025", "OWASP-WSTG", "OWASP-ASVS", "OWASP-API-2023", "NIST-800-53", "PCI-DSS"}

REGEX_MAP = {
    "CWE": re.compile(r"^CWE-\d+$"),
    "OWASP-Top-2025": re.compile(r"^A\d{2}$"),
    "OWASP-WSTG": re.compile(r"^WSTG-\d+(\.\d+){0,2}$"),
    "OWASP-ASVS": re.compile(r"^V\d+\.\d+\.\d+$"),
    "OWASP-API-2023": re.compile(r"^API\d+$"),
    "NIST-800-53": re.compile(r"^[A-Z]+-\d+$"),
    "PCI-DSS": re.compile(r"^req-\d+(\.\d+)*$"),
}

STANDARDS_PRIORITY = ["CWE", "OWASP-Top-2025", "OWASP-WSTG", "OWASP-ASVS", "OWASP-API-2023"]

# ── YAML frontmatter parser (stdlib only, recursive by indentation) ──────
#
# Supports the frontmatter vocabulary of findings/ and chains/ docs:
# block mappings, block sequences (indented or at parent-key indent),
# lists of mappings (`- key: val` + aligned continuation keys), nested
# mappings (`evidence:`, `target_version:`), inline lists (`[a, b]`),
# block scalars (`|`, `>` with +/- chomping), quoted strings with escapes,
# and typed scalars (str/int/float/bool/null). Deliberately NOT supported:
# flow mappings, anchors/aliases, multi-document, tabs. Lenient by design —
# malformed lines are skipped, never fatal (structure is judged by checks,
# not by the parser).

_KEY_RE = re.compile(r"^([\w\-.]+):\s*(.*)$")
_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?(?:\d+\.\d+|\d+\.?\d*[eE][-+]?\d+)$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}

def parse_frontmatter(text):
    """Extract YAML frontmatter between --- markers. Returns dict or None."""
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return None
    value = _parse_yaml(m.group(1))
    return value if isinstance(value, dict) else {}

def _parse_yaml(text):
    """Parse a frontmatter block. Top level must be a mapping; a block that
    parses to anything else (or nothing) degrades to {} — lenient."""
    lines = text.split("\n")
    value, _ = _parse_block(lines, 0, 0)
    return value if isinstance(value, dict) else {}

def _indent_of(line):
    return len(line) - len(line.lstrip(" "))

def _skip_blank(lines, i):
    """Index of the next non-blank, non-comment line (or len(lines))."""
    n = len(lines)
    while i < n:
        s = lines[i].strip()
        if s and not s.startswith("#"):
            return i
        i += 1
    return n

def _parse_block(lines, i, min_indent):
    """Parse the node starting at the next significant line, which must be
    indented at least min_indent. Returns (value, next_index)."""
    i = _skip_blank(lines, i)
    if i >= len(lines):
        return None, i
    indent = _indent_of(lines[i])
    if indent < min_indent:
        return None, i
    s = lines[i].strip()
    if s == "-" or s.startswith("- "):
        return _parse_sequence(lines, i, indent)
    return _parse_mapping(lines, i, indent)

def _parse_mapping(lines, i, indent):
    """Parse a block mapping whose keys sit at `indent`."""
    result = {}
    n = len(lines)
    while True:
        i = _skip_blank(lines, i)
        if i >= n:
            break
        line = lines[i]
        ind = _indent_of(line)
        if ind < indent:
            break
        s = line.strip()
        if ind == indent:
            if s == "-" or s.startswith("- "):
                break  # sequence at mapping indent belongs to the parent key
            m = _KEY_RE.match(s)
            if not m:
                i += 1  # malformed line — skip, never fatal
                continue
            key, rest = m.group(1), m.group(2)
            i += 1
            result[key], i = _parse_value(lines, i, rest, indent)
        else:
            i += 1  # stray deeper line not consumed by any value — skip
    return result, i

def _parse_sequence(lines, i, indent):
    """Parse a block sequence whose `-` items sit at `indent`."""
    items = []
    n = len(lines)
    while True:
        i = _skip_blank(lines, i)
        if i >= n:
            break
        line = lines[i]
        ind = _indent_of(line)
        s = line.strip()
        if ind != indent or not (s == "-" or s.startswith("- ")):
            break  # end of this sequence level
        content = s[1:].strip()
        if content == "":
            # bare '-': the item is the nested block that follows
            item, i = _parse_block(lines, i + 1, indent + 1)
            items.append(item)
            continue
        m = _KEY_RE.match(content)
        if m and content[0] not in "\"'":
            # '- key: value' — mapping item; further keys align with `key`
            after_dash = line[ind + 1:]
            item_indent = ind + 1 + (len(after_dash) - len(after_dash.lstrip(" ")))
            key, rest = m.group(1), m.group(2)
            item, i = _parse_mapping_from_first(lines, i + 1, item_indent, key, rest)
            items.append(item)
        else:
            items.append(_parse_inline_scalar(content))
            i += 1
    return items, i

def _parse_mapping_from_first(lines, i, indent, first_key, first_rest):
    """Parse a mapping whose first pair was on a list-item line; subsequent
    keys align at `indent`."""
    item = {}
    item[first_key], i = _parse_value(lines, i, first_rest, indent)
    n = len(lines)
    while True:
        i = _skip_blank(lines, i)
        if i >= n:
            break
        ind = _indent_of(lines[i])
        if ind < indent:
            break
        s = lines[i].strip()
        if ind == indent:
            m = _KEY_RE.match(s)
            if not m:
                break
            key, rest = m.group(1), m.group(2)
            i += 1
            item[key], i = _parse_value(lines, i, rest, indent)
        else:
            i += 1  # stray deeper line — skip
    return item, i

def _parse_value(lines, i, rest, key_indent):
    """Value of a mapping key: `rest` is what followed `key:` on its line."""
    s = rest.strip()
    if s == "":
        # Nested block (deeper indent), same-indent sequence, or null
        j = _skip_blank(lines, i)
        if j >= len(lines):
            return None, j
        ind = _indent_of(lines[j])
        s2 = lines[j].strip()
        if ind > key_indent:
            return _parse_block(lines, j, key_indent + 1)
        if ind == key_indent and (s2 == "-" or s2.startswith("- ")):
            return _parse_sequence(lines, j, ind)
        return None, j
    if s[0] in "\"'":
        return _parse_quoted(s), i
    s = re.split(r"\s#", s, 1)[0].strip()  # strip trailing comment
    if s == "":
        return None, i
    if s[0] in "|>":
        return _parse_block_scalar(lines, i, s, key_indent)
    if s.startswith("["):
        return _parse_inline_list(s), i
    return _parse_scalar(s), i

def _parse_block_scalar(lines, i, header, key_indent):
    """Block scalar `|`/`>` with optional +/- chomping. Body lines are the
    following lines indented deeper than the key."""
    literal = header[0] == "|"
    chomp = header[1:]
    body = []
    j = i
    n = len(lines)
    while j < n:
        line = lines[j]
        if line.strip() == "":
            body.append("")
            j += 1
            continue
        if _indent_of(line) <= key_indent:
            break
        body.append(line)
        j += 1
    while body and body[-1] == "":
        body.pop()
    indents = [_indent_of(b) for b in body if b != ""]
    common = min(indents) if indents else 0
    content = [b[common:] if b != "" else "" for b in body]
    if literal:
        val = "\n".join(content)
    else:  # folded: single newline → space, blank line → newline
        parts = []
        for k, b in enumerate(content):
            if b == "":
                parts.append("\n")
            elif k == 0 or content[k - 1] == "":
                parts.append(b)
            else:
                parts.append(" " + b)
        val = "".join(parts)
    if chomp != "-" and val != "":
        val += "\n"
    return val, j

def _parse_quoted(s):
    """Quoted scalar starting at s[0]; content after the closing quote
    (trailing comments) is ignored. Double quotes honor \\-escapes."""
    if s[0] == '"':
        out = []
        k = 1
        n = len(s)
        while k < n:
            c = s[k]
            if c == "\\" and k + 1 < n:
                nxt = s[k + 1]
                if nxt in ("u", "U"):  # \uXXXX / \UXXXXXXXX unicode escape
                    hex_len = 4 if nxt == "u" else 8
                    digits = s[k + 2:k + 2 + hex_len]
                    if len(digits) == hex_len:
                        try:
                            out.append(chr(int(digits, 16)))
                            k += 2 + hex_len
                            continue
                        except ValueError:
                            pass
                    out.append("\\" + nxt)
                    k += 2
                    continue
                out.append(_ESCAPES.get(nxt, "\\" + nxt))
                k += 2
                continue
            if c == '"':
                break
            out.append(c)
            k += 1
        return "".join(out)
    out = []  # single-quoted: '' is an escaped quote
    k = 1
    n = len(s)
    while k < n:
        if s[k] == "'" and k + 1 < n and s[k + 1] == "'":
            out.append("'")
            k += 2
            continue
        if s[k] == "'":
            break
        out.append(s[k])
        k += 1
    return "".join(out)

def _parse_inline_list(s):
    """Inline list `[a, b, ...]`; items are typed scalars, quotes aware."""
    inner = s[1:-1] if s.endswith("]") else s[1:]
    if inner.strip() == "":
        return []
    parts, cur, quote = [], [], None
    for c in inner:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
            continue
        if c in "\"'":
            quote = c
            cur.append(c)
            continue
        if c == ",":
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    parts.append("".join(cur))
    return [_parse_inline_scalar(p) for p in parts if p.strip() != ""]

def _parse_inline_scalar(s):
    """One scalar already stripped of its surrounding syntax: quoted string
    or comment-stripped typed scalar."""
    s = s.strip()
    if s == "":
        return None
    if s[0] in "\"'":
        return _parse_quoted(s)
    s = re.split(r"\s#", s, 1)[0].strip()
    if s == "":
        return None
    return _parse_scalar(s)

def _parse_scalar(s):
    """Typed scalar: bool/int/float/null/str (comment-stripped input)."""
    if s in ("~", "null", "Null", "NULL", "none", "None"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(s):
        return int(s)
    if _FLOAT_RE.match(s):
        return float(s)
    return s

# ── Helpers ──────────────────────────────────────────────────────────────

def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None

def glob_md(path):
    if not path.exists():
        return []
    return sorted(path.glob("*.md"))

def glob_files(path):
    if not path.exists():
        return []
    return sorted(path.iterdir())

# ── Grader ───────────────────────────────────────────────────────────────

class Grader:
    def __init__(self, target_dir, verbose=False):
        self.target = Path(target_dir)
        self.rt = self.target / ".red-team"
        self.verbose = verbose
        self.checks = []
        self._findings_cache = None
        self._index_ids_cache = None
        self._report_ids_cache = None

    def emit(self, check_id, severity, msg, expected=None, actual=None):
        self.checks.append({
            "id": check_id,
            "severity": severity,
            "msg": msg,
            "expected": expected,
            "actual": actual,
        })
        if self.verbose or severity != "PASS":
            label = {"PASS": "  PASS", "WARN": "  WARN", "FAIL": "  FAIL"}.get(severity, "  ????")
            print(f"{label}  {check_id}  {msg}")

    # ── Finding file parsing ────────────────────────────────────────────

    def _findings(self):
        if self._findings_cache is not None:
            return self._findings_cache
        findings = {}
        for fpath in glob_md(self.rt / "findings"):
            text = read(fpath)
            fm = parse_frontmatter(text)
            if fm and fm.get("id"):
                findings[fm["id"]] = {
                    "path": fpath,
                    "fm": fm,
                    "text": text,
                    "standards": fm.get("standards") or [],
                }
        self._findings_cache = findings
        return findings

    def _finding_ids(self):
        return set(self._findings().keys())

    def _index_ids(self):
        if self._index_ids_cache is not None:
            return self._index_ids_cache
        text = read(self.rt / "findings" / "index.md")
        if not text:
            self._index_ids_cache = set()
            return set()
        ids = set()
        for m in re.finditer(r"\b(RT-\d{3})\b", text):
            ids.add(m.group(1))
        self._index_ids_cache = ids
        return ids

    def _report_ids(self):
        if self._report_ids_cache is not None:
            return self._report_ids_cache
        text = read(self.rt / "REPORT.md")
        if not text:
            self._report_ids_cache = set()
            return set()
        ids = set()
        for m in re.finditer(r"\b(RT-\d{3})\b", text):
            ids.add(m.group(1))
        self._report_ids_cache = ids
        return ids

    def _traceability(self):
        text = read(self.rt / "traceability.json")
        if not text:
            return None, set()
        try:
            data = json.loads(text)
            tids = set(data.get("findings", {}).keys())
            return data, tids
        except json.JSONDecodeError:
            return None, set()

    def _csv_ids(self):
        text = read(self.rt / "exports" / "findings.csv")
        if not text:
            return set()
        ids = set()
        for line in text.strip().split("\n")[1:]:  # skip header
            m = re.match(r"^RT-\d{3}", line)
            if m:
                ids.add(m.group(0))
        return ids

    def _sarif_data(self):
        text = read(self.rt / "exports" / "findings.sarif")
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _vex_data(self):
        text = read(self.rt / "exports" / "vex.json")
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _remediation_sections(self):
        """Parse remediation-requirements.md into {RT-NNN: {fr:[], ac:[], dp:[]}}."""
        text = read(self.rt / "remediation-requirements.md")
        if not text:
            return {}
        sections = {}
        # Split on ## headings
        current_id = None
        current_block = None
        for line in text.split("\n"):
            m = re.match(r"^##\s+(RT-\d{3})", line)
            if m:
                if current_id and current_block:
                    sections[current_id] = self._parse_rem_block(current_block)
                current_id = m.group(1)
                current_block = []
                continue
            if current_block is not None:
                current_block.append(line)
        if current_id and current_block:
            sections[current_id] = self._parse_rem_block(current_block)
        return sections

    def _parse_rem_block(self, lines):
        block = "\n".join(lines)
        result = {"fr": [], "nfr": [], "ac": [], "dp": []}
        # Extract acceptance criteria IDs
        for m in re.finditer(r"(?:###\s*(?:Acceptance [Cc]riteria|[Cc]riteria))\n(.*?)(?=\n###|\Z)", block, re.DOTALL):
            body = m.group(1)
            for acm in re.finditer(r"(AC-\d{3}-\d+)", body):
                result["ac"].append(acm.group(1))
        # Extract decision point IDs
        for m in re.finditer(r"(?:###\s*Decision [Pp]oints)\n(.*?)(?=\n###|\Z)", block, re.DOTALL):
            body = m.group(1)
            for dpm in re.finditer(r"(DP-\d{3}-\d+)", body):
                result["dp"].append(dpm.group(1))
        # Extract FR IDs
        for m in re.finditer(r"(?:###\s*Functional [Rr]equirements)\n(.*?)(?=\n###|\Z)", block, re.DOTALL):
            body = m.group(1)
            for frm in re.finditer(r"(FR-\d{3}-\d+)", body):
                result["fr"].append(frm.group(1))
        # Extract NFR IDs
        for m in re.finditer(r"(?:###\s*Non-Functional [Rr]equirements)\n(.*?)(?=\n###|\Z)", block, re.DOTALL):
            body = m.group(1)
            for nfrm in re.finditer(r"(NFR-\d{3}-\d+)", body):
                result["nfr"].append(nfrm.group(1))
        return result

    # ── G1: Finding frontmatter integrity ──────────────────────────────

    @staticmethod
    def _key_tokens(title):
        """Tokenize a finding title into meaningful key tokens.

        Lowercases, splits on non-alphanumerics, drops tokens shorter than 4
        chars and a small stoplist. Used by G5.1 (threat-model row context) and
        G1.8 (duplicate detection).
        """
        STOPWORDS = {"the", "and", "via", "post", "route", "all", "any", "for",
                     "with", "from", "using", "application", "server", "project",
                     "that", "this", "are", "was", "not", "but", "has", "had"}
        return {t for t in re.split(r"[^a-z0-9]+", title.lower()) if len(t) >= 4 and t not in STOPWORDS}

    @staticmethod
    def _frontmatter_problem(fpath):
        """Reason string if `fpath` cannot be consumed as a finding, else None.

        Files that fail here are silently dropped by `_findings()` (which only
        keeps parseable frontmatter with an `id`). G1.0 surfaces them so an
        unreadable finding never vanishes from the report without a trace.
        """
        text = read(fpath)
        if text is None:
            return "file unreadable"
        fm = parse_frontmatter(text)
        if fm is None:
            return "no YAML frontmatter (missing --- block)"
        if not fm:
            return "empty frontmatter"
        if not fm.get("id"):
            return f"frontmatter parseable but no id (keys: {', '.join(sorted(fm))[:60]})"
        return None

    def _check_g1(self):
        findings = self._findings()

        # G1.0 — deterministic parse guard. Structure is the grader's job:
        # every findings/*.md must yield a finding (parseable, non-empty
        # frontmatter carrying an id), otherwise the file is flagged. Semantic
        # judgment stays with the skeptic gate (fresh-context subagent) —
        # separate roles, no redundancy. index.md is the index, not a finding.
        finding_files = [p for p in glob_md(self.rt / "findings") if p.name != "index.md"]
        dropped = []
        for fpath in finding_files:
            reason = self._frontmatter_problem(fpath)
            if reason:
                dropped.append(f"{fpath.name}: {reason}")
        if dropped:
            self.emit("G1.0", "FAIL",
                      f"finding file(s) not parseable into a finding: {dropped[:5]}"
                      + (f" (+{len(dropped) - 5} more)" if len(dropped) > 5 else ""))
        elif finding_files:
            self.emit("G1.0", "PASS",
                      f"all {len(finding_files)} finding file(s) have parseable frontmatter with an id")
        else:
            self.emit("G1.0", "FAIL", "No finding files found in findings/")

        if not findings:
            return

        for fid, fdata in findings.items():
            fm = fdata["fm"]
            # G1.1 — required keys
            required = {"id", "schema_version", "title", "category", "severity", "cwe", "status", "confidence"}
            missing = required - set(fm.keys())
            if missing:
                self.emit("G1.1", "FAIL", f"{fid}: missing required keys: {sorted(missing)}", list(required), list(fm.keys()))
                continue

            # G1.2 — schema version
            if fm.get("schema_version") != SCHEMA_VERSION_REQUIRED:
                self.emit("G1.2", "FAIL", f"{fid}: schema_version is {fm.get('schema_version')}, expected {SCHEMA_VERSION_REQUIRED}",
                          SCHEMA_VERSION_REQUIRED, fm.get("schema_version"))
            else:
                self.emit("G1.2", "PASS", f"{fid}: schema_version = {SCHEMA_VERSION_REQUIRED}")

            # G1.3 — Open findings have proper confidence
            if fm.get("status") == "Open":
                conf = fm.get("confidence", "")
                if conf not in ("High-verified", "High-static"):
                    self.emit("G1.3", "FAIL", f"{fid}: Open finding has confidence '{conf}', expected High-verified or High-static",
                              "High-verified or High-static", conf)
                else:
                    self.emit("G1.3", "PASS", f"{fid}: Open with confidence {conf}")

            # G1.4 — FP/Duplicate severity N/A
            if fm.get("status") in ("False Positive", "Duplicate") and fm.get("severity") != "N/A":
                self.emit("G1.4", "FAIL", f"{fid}: {fm.get('status')} finding has severity '{fm.get('severity')}', expected N/A",
                          "N/A", fm.get("severity"))

            # G1.5 — evidence block iff High-verified
            has_ev = "evidence" in fm and fm["evidence"] is not None and fm["evidence"] != "null"
            if fm.get("confidence") == "High-verified" and not has_ev:
                self.emit("G1.5", "FAIL", f"{fid}: High-verified but no evidence block")
            elif fm.get("confidence") != "High-verified" and has_ev:
                self.emit("G1.5", "WARN", f"{fid}: evidence block present but confidence is '{fm.get('confidence')}' — should be High-verified")

            # G1.6 — standards regex compliance
            standards = fdata["standards"]
            for s in standards:
                fw = s.get("framework") if isinstance(s, dict) else None
                rid = s.get("requirement_id") if isinstance(s, dict) else None
                if not fw or not rid:
                    continue
                if fw not in CLOSED_VOCAB:
                    self.emit("G1.6", "FAIL", f"{fid}: unknown framework '{fw}' in standards")
                else:
                    rx = REGEX_MAP.get(fw)
                    if rx and not rx.match(rid):
                        self.emit("G1.6", "FAIL", f"{fid}: {fw} regex rejects '{rid}'")

            # G1.7 — 5-row cap + priority order
            if len(standards) > 5:
                self.emit("G1.7", "FAIL", f"{fid}: {len(standards)} standards rows, max is 5")
            # Priority: CWE first, then Top-10, then WSTG, then ASVS, then API-2023
            seen_fws = []
            for s in standards:
                fw = s.get("framework") if isinstance(s, dict) else None
                if fw:
                    seen_fws.append(fw)
            expected_order = [fw for fw in STANDARDS_PRIORITY if fw in seen_fws]
            if seen_fws and seen_fws != expected_order:
                self.emit("G1.7", "FAIL", f"{fid}: standards priority order is {seen_fws}, expected {expected_order}")

        # G1.8 — duplicate finding detection (WARN).
        # Two Open findings sharing the same CWE AND (same location prefix OR
        # >=2 shared title tokens) are candidates for merging. WARN, not FAIL —
        # legitimate overlapping findings exist (different layers).
        open_findings = [(fid, fd["fm"]) for fid, fd in findings.items() if fd["fm"].get("status") == "Open"]
        dup_warns = []
        for i, (fid_a, fm_a) in enumerate(open_findings):
            for fid_b, fm_b in open_findings[i + 1:]:
                same_cwe = bool(fm_a.get("cwe")) and fm_a.get("cwe") == fm_b.get("cwe")
                loc_a = (fm_a.get("location") or "").split(":")[0].strip()
                loc_b = (fm_b.get("location") or "").split(":")[0].strip()
                same_loc_prefix = bool(loc_a and loc_b and (loc_a.startswith(loc_b) or loc_b.startswith(loc_a)))
                title_overlap = len(self._key_tokens(fm_a.get("title", "")) & self._key_tokens(fm_b.get("title", ""))) >= 2
                if same_cwe and (same_loc_prefix or title_overlap):
                    reason = f"same CWE {fm_a.get('cwe')}"
                    if same_loc_prefix:
                        reason += f" + same location prefix '{loc_a}'"
                    if title_overlap:
                        reason += " + title token overlap"
                    dup_warns.append(f"{fid_a} & {fid_b}: {reason}")
        if dup_warns:
            self.emit("G1.8", "WARN",
                      f"Potential duplicate findings (review for merge): {dup_warns[:5]}")
        else:
            self.emit("G1.8", "PASS",
                      f"No duplicate finding candidates among {len(open_findings)} Open findings")

        # G1.9 — canonical category vocabulary (WARN).
        # Off-vocabulary categories (abbreviations, OWASP names, older
        # generations of the taxonomy) silently drift the artifacts: the
        # threat model, index, and exports then disagree with the findings.
        offenders = sorted(
            f"{fid}: {fd['fm'].get('category')}"
            for fid, fd in findings.items()
            if fd["fm"].get("category") and fd["fm"].get("category") not in CANONICAL_CATEGORIES
        )
        if offenders:
            self.emit("G1.9", "WARN",
                      f"non-canonical category values (see SKILL.md 'Probe Categories'): {offenders[:5]}"
                      + (f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""))
        else:
            self.emit("G1.9", "PASS",
                      f"all {len(findings)} finding(s) use canonical categories")

        # G1.10 — skeptic-review completeness (WARN, gated).
        # Evaluated only when at least one finding records a skeptic_review
        # value; sessions run without the skeptic gate stay silent.
        with_skeptic = [fid for fid, fd in findings.items() if fd["fm"].get("skeptic_review")]
        if with_skeptic:
            missing = sorted(
                fid for fid, fd in findings.items()
                if fd["fm"].get("confidence") in ("High-verified", "High-static")
                and not fd["fm"].get("skeptic_review")
            )
            invalid = sorted(
                f"{fid}: {fd['fm'].get('skeptic_review')}"
                for fid, fd in findings.items()
                if fd["fm"].get("skeptic_review") and fd["fm"].get("skeptic_review") not in SKEPTIC_VERDICTS
            )
            if missing or invalid:
                parts = []
                if missing:
                    parts.append(f"missing on {missing[:5]}")
                if invalid:
                    parts.append(f"invalid values {invalid[:5]}")
                self.emit("G1.10", "WARN", "skeptic_review incomplete: " + "; ".join(parts))
            else:
                self.emit("G1.10", "PASS",
                          f"skeptic_review recorded on all {len(with_skeptic)} finding(s) that carry it")

        self.emit("G1", "PASS", f"Checked {len(findings)} finding file(s)")

    # ── G2: Cross-artifact consistency ──────────────────────────────────

    def _check_g2(self):
        finding_ids = self._finding_ids()
        index_ids = self._index_ids()
        report_ids = self._report_ids()
        rem_sections = self._remediation_sections()

        # G2.1 — finding sets agree
        if finding_ids != index_ids:
            missing_in_index = finding_ids - index_ids
            extra_in_index = index_ids - finding_ids
            parts = []
            if missing_in_index:
                parts.append(f"in findings but not index: {sorted(missing_in_index)}")
            if extra_in_index:
                parts.append(f"in index but not findings: {sorted(extra_in_index)}")
            self.emit("G2.1", "FAIL", "findings/*.md ↔ index.md ID mismatch: " + "; ".join(parts),
                      sorted(finding_ids), sorted(index_ids))

        if finding_ids != report_ids:
            missing_in_report = finding_ids - report_ids
            extra_in_report = report_ids - finding_ids
            parts = []
            if missing_in_report:
                parts.append(f"in findings but not REPORT: {sorted(missing_in_report)}")
            if extra_in_report:
                parts.append(f"in REPORT but not findings: {sorted(extra_in_report)}")
            self.emit("G2.1", "FAIL", "findings/*.md ↔ REPORT.md ID mismatch: " + "; ".join(parts))

        if finding_ids == index_ids and finding_ids == report_ids:
            self.emit("G2.1", "PASS", f"findings/index/report all agree on {len(finding_ids)} IDs")

        # G2.2 — traceability.json entries match
        trace_data, trace_ids = self._traceability()
        if trace_data is not None:
            missing_in_trace = finding_ids - trace_ids
            extra_in_trace = trace_ids - finding_ids
            if missing_in_trace:
                self.emit("G2.2", "FAIL", f"traceability.json missing entries: {sorted(missing_in_trace)}",
                          sorted(finding_ids), sorted(trace_ids))
            # Title consistency
            title_mismatches = []
            for fid, fdata in self._findings().items():
                canon_title = fdata["fm"].get("title", "")
                trace_entry = trace_data.get("findings", {}).get(fid, {})
                trace_title = trace_entry.get("title", "")
                if canon_title and trace_title and canon_title != trace_title:
                    title_mismatches.append(f"{fid}: '{trace_title}' vs finding '{canon_title}'")
            if title_mismatches:
                self.emit("G2.2", "FAIL", f"traceability.json titles diverge: {title_mismatches[:5]}")

            if not missing_in_trace and not title_mismatches:
                self.emit("G2.2", "PASS", f"traceability.json has {len(trace_ids)} entries with matching titles")

            # G2.3 — schema_version
            trace_sv = trace_data.get("schema_version")
            if trace_sv != SCHEMA_VERSION_REQUIRED:
                self.emit("G2.3", "FAIL", f"traceability.json schema_version={trace_sv}, expected {SCHEMA_VERSION_REQUIRED}",
                          SCHEMA_VERSION_REQUIRED, trace_sv)
            else:
                self.emit("G2.3", "PASS", f"traceability.json schema_version={SCHEMA_VERSION_REQUIRED}")
        else:
            self.emit("G2.2", "FAIL", "traceability.json not found or invalid JSON")
            self.emit("G2.3", "FAIL", "traceability.json not found or invalid JSON")

        # G2.4 — remediation-requirements.md has section for each Open finding
        open_ids = {fid for fid, fd in self._findings().items() if fd["fm"].get("status") == "Open"}
        if open_ids:
            missing_rem = open_ids - set(rem_sections.keys())
            if missing_rem:
                self.emit("G2.4", "FAIL", f"Open findings missing from remediation-requirements.md: {sorted(missing_rem)}")

        # G2.5 — Acceptance Criteria heading casing
        rem_text = read(self.rt / "remediation-requirements.md")
        if rem_text:
            lower_count = rem_text.count("### Acceptance criteria")
            upper_count = rem_text.count("### Acceptance Criteria")
            if lower_count > 0:
                self.emit("G2.5", "FAIL",
                          f"remediation-requirements.md has {lower_count} lowercase '### Acceptance criteria' "
                          f"— should be '### Acceptance Criteria' (capital C)",
                          expected=0, actual=lower_count)
            elif upper_count > 0:
                self.emit("G2.5", "PASS",
                          f"All {upper_count} Acceptance Criteria headings use capital C")

        # G2.6 — traceability AC/DP match remediation-requirements.md (alignment-first)
        if trace_data is not None and rem_sections:
            mismatch_msgs = []
            open_ids_g26 = {fid for fid, fd in self._findings().items() if fd["fm"].get("status") == "Open"}
            for fid in rem_sections:
                trace_entry = trace_data.get("findings", {}).get(fid, {})
                trace_ac = set(trace_entry.get("acceptance_criteria", []))
                trace_dp = set(trace_entry.get("decision_points", []))
                rem_ac = set(rem_sections[fid].get("ac", []))
                rem_dp = set(rem_sections[fid].get("dp", []))
                if rem_ac and rem_ac != trace_ac:
                    mismatch_msgs.append(f"{fid}: AC rem={sorted(rem_ac)} trace={sorted(trace_ac)}")
                if rem_dp and rem_dp != trace_dp:
                    mismatch_msgs.append(f"{fid}: DP rem={sorted(rem_dp)} trace={sorted(trace_dp)}")
            # Also flag Open findings missing ACs in traceability when ACs exist in rem
            for fid in open_ids_g26:
                trace_entry = trace_data.get("findings", {}).get(fid, {})
                rem_ac = set(rem_sections.get(fid, {}).get("ac", []))
                if rem_ac and not trace_entry.get("acceptance_criteria"):
                    mismatch_msgs.append(f"{fid}: has {len(rem_ac)} ACs in rem but 0 in traceability")
            if mismatch_msgs:
                self.emit("G2.6", "FAIL", f"traceability.json AC/DP drift: {'; '.join(mismatch_msgs[:6])}")
            else:
                self.emit("G2.6", "PASS", "traceability.json AC/DP arrays match remediation-requirements.md")
        else:
            self.emit("G2.6", "FAIL", "traceability.json or remediation-requirements.md missing")

        self.emit("G2", "PASS", "Cross-artifact consistency checks complete")

    # ── G3: Exports closure ────────────────────────────────────────────

    def _check_g3(self):
        finding_ids = self._finding_ids()

        # G3.1 — CSV
        csv_ids = self._csv_ids()
        missing_csv = finding_ids - csv_ids
        extra_csv = csv_ids - finding_ids
        if missing_csv:
            self.emit("G3.1", "FAIL", f"CSV missing rows: {sorted(missing_csv)}", sorted(finding_ids), sorted(csv_ids))
        elif extra_csv:
            self.emit("G3.1", "FAIL", f"CSV has extra rows: {sorted(extra_csv)}")
        else:
            self.emit("G3.1", "PASS", f"CSV has {len(csv_ids)} rows matching findings")

        # G3.2 — SARIF
        sarif = self._sarif_data()
        if sarif:
            results = sarif.get("runs", [{}])[0].get("results", [])
            sarif_rules = sarif.get("runs", [{}])[0].get("tool", {}).get("driver", {}).get("rules", [])
            sarif_ids = set()
            for r in results:
                rule_id = r.get("ruleId", "")
                m = re.match(r"CWE-(\d+)", rule_id)
                if m:
                    # Map back to RT-NNN via the rule
                    for fid, fd in self._findings().items():
                        if fd["fm"].get("cwe", "").replace("CWE-", "") == m.group(1):
                            sarif_ids.add(fid)
            missing_sarif = finding_ids - sarif_ids
            if missing_sarif:
                self.emit("G3.2", "FAIL", f"SARIF missing results: {sorted(missing_sarif)}", len(finding_ids), len(sarif_ids))
            else:
                self.emit("G3.2", "PASS", f"SARIF has {len(sarif_ids)} results matching findings")

            # Per-result standards property check
            for result in results:
                props = result.get("properties", {})
                if "standards" not in props:
                    self.emit("G3.2", "FAIL", f"SARIF result {result.get('ruleId')} missing properties.standards")
        else:
            self.emit("G3.2", "FAIL", "findings.sarif not found or invalid JSON")

        # G3.3 — VEX
        vex = self._vex_data()
        if vex:
            statements = vex.get("statements", [])
            vex_ids = set()
            for stmt in statements:
                vname = stmt.get("vulnerability", {}).get("name", "")
                if re.match(r"^RT-\d{3}$", vname):
                    vex_ids.add(vname)
            missing_vex = finding_ids - vex_ids
            if missing_vex:
                self.emit("G3.3", "FAIL", f"VEX missing statements: {sorted(missing_vex)}", sorted(finding_ids), sorted(vex_ids))
            else:
                self.emit("G3.3", "PASS", f"VEX has {len(vex_ids)} statements matching findings")

            # G3.4 — cve field doesn't carry CWE ids
            cwe_in_cve = []
            for stmt in statements:
                cve_field = stmt.get("vulnerability", {}).get("cve", "")
                if cve_field.startswith("CWE-"):
                    cwe_in_cve.append(f"{stmt.get('vulnerability',{}).get('name','')}: {cve_field}")
            if cwe_in_cve:
                self.emit("G3.4", "FAIL", f"VEX vulnerability.cve carries CWE ids: {cwe_in_cve}")
            else:
                self.emit("G3.4", "PASS", "No CWE ids in VEX vulnerability.cve fields")

            # G3.5 — VEX status matches finding confidence/status
            status_mismatches = []
            for stmt in statements:
                vname = stmt.get("vulnerability", {}).get("name", "")
                vex_status = stmt.get("status", "")
                fdata = self._findings().get(vname)
                if not fdata:
                    continue
                fm = fdata["fm"]
                finding_status = fm.get("status", "")
                confidence = fm.get("confidence", "")
                if finding_status == "Open" and confidence == "High-verified" and vex_status != "known_affected":
                    status_mismatches.append(f"{vname}: VEX={vex_status}, expected 'known_affected' for High-verified Open")
                elif finding_status == "Open" and confidence == "High-static" and vex_status != "under_investigation":
                    status_mismatches.append(f"{vname}: VEX={vex_status}, expected 'under_investigation' for High-static Open")
                elif finding_status == "False Positive" and vex_status != "not_affected":
                    status_mismatches.append(f"{vname}: VEX={vex_status}, expected 'not_affected' for FP")
                elif finding_status in ("Fixed", "Remediated") and vex_status != "fixed":
                    status_mismatches.append(f"{vname}: VEX={vex_status}, expected 'fixed' for {finding_status}")
            if status_mismatches:
                self.emit("G3.5", "FAIL", "; ".join(status_mismatches[:5]))
            else:
                self.emit("G3.5", "PASS", "VEX statuses match finding status/confidence")
        else:
            self.emit("G3.3", "FAIL", "vex.json not found or invalid JSON")

        # G3.6 — exports freshness vs findings
        if self._findings() and (vex or sarif):
            from datetime import datetime, timezone
            # Safely parse ISO 8601 timestamp, stripping trailing Z
            def _parse_iso(ts):
                try:
                    return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc) if ts else None
                except (ValueError, AttributeError):
                    return None
            newest_mtime = max(
                os.path.getmtime(fdata["path"]) for fdata in self._findings().values()
            )
            newest_finding_dt = datetime.fromtimestamp(newest_mtime, tz=timezone.utc)
            stale = []
            vex_ts = _parse_iso(vex.get("timestamp")) if vex else None
            if vex_ts and vex_ts < newest_finding_dt:
                stale.append(f"VEX ({vex_ts.isoformat()}) < findings ({newest_finding_dt.isoformat()})")
            if sarif:
                sarif_ts_str = (sarif.get("runs", [{}])[0]
                                .get("invocations", [{}])[0]
                                .get("endTime", None))
                sarif_ts = _parse_iso(sarif_ts_str)
                if sarif_ts and sarif_ts < newest_finding_dt:
                    stale.append(f"SARIF ({sarif_ts.isoformat()}) < findings ({newest_finding_dt.isoformat()})")
            if stale:
                self.emit("G3.6", "WARN", "Exports stale: " + "; ".join(stale))
            else:
                self.emit("G3.6", "PASS", "Exports are fresh relative to findings")

        self.emit("G3", "PASS", "Export closure checks complete")

    # ── G4: Evidence cleanliness ────────────────────────────────────────

    def _check_g4(self):
        findings = self._findings()
        evidence_dir = self.rt / "evidence"
        ev_dirs = set()
        if evidence_dir.exists():
            for d in evidence_dir.iterdir():
                if d.is_dir():
                    ev_dirs.add(d.name)

        # G4.1 — High-verified findings have evidence
        hv_ids = set()
        for fid, fd in findings.items():
            if fd["fm"].get("confidence") == "High-verified":
                hv_ids.add(fid)
                ev_path = evidence_dir / f"RT-{fid.replace('RT-', '')}"
                if not ev_path.exists():
                    self.emit("G4.1", "FAIL", f"{fid}: High-verified but no evidence/ directory")
                else:
                    files = list(ev_path.iterdir())
                    has_req_resp = any(f.name.endswith("request.http") for f in files) and any(f.name.endswith("response.http") for f in files)
                    has_instrumented = any(f.name.endswith(".instrumented.md") for f in files)
                    if has_req_resp:
                        self.emit("G4.1", "PASS", f"{fid}: has evidence with request+response files")
                    elif has_instrumented:
                        self.emit("G4.1", "PASS", f"{fid}: has instrumented evidence capture ({sum(1 for f in files if f.name.endswith('.instrumented.md'))} .instrumented.md file(s))")
                    else:
                        self.emit("G4.1", "FAIL", f"{fid}: evidence/ directory missing request+response .http pair or *.instrumented.md capture")

        # G4.2 — Empty evidence dirs should have SKIPPED.md
        for dname in ev_dirs:
            if dname.startswith("RT-"):
                ev_path = evidence_dir / dname
                files = list(ev_path.iterdir())
                if not files:
                    skipped = ev_path / "SKIPPED.md"
                    if not skipped.exists():
                        self.emit("G4.2", "FAIL", f"evidence/{dname}/ is empty — must have SKIPPED.md or evidence files")
                    else:
                        self.emit("G4.2", "PASS", f"evidence/{dname}/ has SKIPPED.md")

        # G4.3 — X-Paladin-Probe header in request files
        for dname in ev_dirs:
            if dname.startswith("RT-"):
                for f in (evidence_dir / dname).glob("*request*"):
                    content = read(f)
                    if content and "X-Paladin-Probe" not in content:
                        self.emit("G4.3", "FAIL", f"evidence/{dname}/{f.name}: missing X-Paladin-Probe header")

        # G4.4 — evidence manifest integrity (WARN; silent when no manifests).
        # manifest.sha256 lines are `<sha256>  <filename>` (SHA256SUMS format,
        # written by scripts/probe.sh). A missing file or hash mismatch means
        # evidence was edited — or lost — after capture.
        manifests = sorted(evidence_dir.glob("*/manifest.sha256")) if evidence_dir.exists() else []
        drift = []
        for mf in manifests:
            for line in (read(mf) or "").splitlines():
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                expected, fname = parts[0], parts[1].strip()
                fpath = mf.parent / fname
                if not fpath.exists():
                    drift.append(f"{mf.parent.name}/{fname}: missing")
                else:
                    actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
                    if actual != expected:
                        drift.append(f"{mf.parent.name}/{fname}: hash mismatch")
        if manifests and drift:
            self.emit("G4.4", "WARN",
                      f"evidence manifest drift (changed or missing after capture): {drift[:5]}")
        elif manifests:
            self.emit("G4.4", "PASS", f"all {len(manifests)} evidence manifest(s) verified")

        self.emit("G4", "PASS", "Evidence cleanliness checks complete")

    # ── G5: Threat model & surface hygiene ──────────────────────────────

    def _check_g5(self):
        # G5.1 — threat-model.md mentions all Open findings
        tm_text = read(self.rt / "threat-model.md")
        open_ids = {fid for fid, fd in self._findings().items() if fd["fm"].get("status") == "Open"}
        if tm_text and open_ids:
            missing_tm = []
            for oid in sorted(open_ids):
                if oid not in tm_text:
                    missing_tm.append(oid)
            if missing_tm:
                self.emit("G5.1", "FAIL", f"threat-model.md missing Open findings: {missing_tm}")
            else:
                self.emit("G5.1", "PASS", f"threat-model.md mentions all {len(open_ids)} Open findings")

            # G5.1 (extended) — semantic row-context check (WARN).
            # Every table row that references an RT-NNN must share >=2 key tokens
            # with the finding's frontmatter title. Catches wrong-ID associations
            # (e.g. RT-006 'path-to-regexp ReDoS' mapped to a CORS row).
            tm_tables = []
            for line in tm_text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("|"):
                    continue
                cells = [c.strip() for c in stripped.strip("|").split("|")]
                if len(cells) < 2:
                    continue
                for c in cells:
                    for m in re.finditer(r"RT-\d{3}", c):
                        ctx = " ".join(x for x in cells if x != m.group(0))
                        tm_tables.append((m.group(0), ctx))
            semantic_warns = []
            for fid in sorted(open_ids):
                title = self._findings()[fid]["fm"].get("title", "")
                if not title:
                    continue
                kt = self._key_tokens(title)
                if not kt:
                    continue
                rows_for_fid = [c2 for (rid, c2) in tm_tables if rid == fid]
                if not rows_for_fid:
                    continue  # handled by the presence check above
                all_text = " ".join(rows_for_fid).lower()
                hits = sum(1 for t in kt if t in all_text)
                if hits < 2:
                    semantic_warns.append(
                        f"{fid}: title tokens {sorted(kt)} not matched in threat-model rows (got {hits})")
            if semantic_warns:
                self.emit("G5.1", "WARN",
                          f"threat-model row context doesn't match finding titles: {semantic_warns[:5]}")
            else:
                self.emit("G5.1", "PASS",
                          f"threat-model rows match title context for all {len(open_ids)} Open findings")

        # G5.2 — REPORT.md Summary table reconciles with findings
        report_text = read(self.rt / "REPORT.md")
        findings = self._findings()
        if report_text and findings:
            # 1. Parse Summary table severity counts. Column layout is detected
            #    from the header row (Open / Static-Only* / Fixed) — not hardcoded.
            summary_counts = {"Open": {}, "Static-Only": {}, "Fixed": {}}
            col_index = {}  # "Open" -> column index
            in_summary = False
            for line in report_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("## Summary"):
                    in_summary = True
                    continue
                if in_summary and stripped.startswith("## "):
                    break
                if in_summary and stripped.startswith("|"):
                    cells = [c.strip() for c in stripped.strip("|").split("|")]
                    if cells and cells[0] == "Severity":
                        for idx, c in enumerate(cells):
                            if c == "Open":
                                col_index["Open"] = idx
                            elif c.startswith("Static-Only") or c.startswith("Static Only"):
                                col_index["Static-Only"] = idx
                            elif c == "Fixed":
                                col_index["Fixed"] = idx
                        continue
                    if cells and cells[0] in {"Critical", "High", "Medium", "Low"}:
                        for col, idx in col_index.items():
                            if len(cells) > idx:
                                try:
                                    summary_counts[col][cells[0]] = int(cells[idx].replace(",", ""))
                                except ValueError:
                                    pass
            # 2. Compute expected counts from frontmatter.
            #    Open column = Open + High-verified; Static-Only = Open + High-static;
            #    Fixed = Fixed/Remediated. Duplicate findings are excluded from all counts.
            expected_counts = {"Open": {}, "Static-Only": {}, "Fixed": {}}
            for fid, fd in findings.items():
                fm = fd["fm"]
                if fm.get("status") == "Duplicate":
                    continue
                sev = fm.get("severity", "?")
                if fm.get("status") == "Open":
                    if fm.get("confidence") == "High-verified":
                        col = "Open"
                    elif fm.get("confidence") == "High-static":
                        col = "Static-Only"
                    else:
                        continue
                    expected_counts[col][sev] = expected_counts[col].get(sev, 0) + 1
                elif fm.get("status") in ("Fixed", "Remediated"):
                    expected_counts["Fixed"][sev] = expected_counts["Fixed"].get(sev, 0) + 1
            # 3. Compare counts
            count_mismatch = []
            for col in ("Open", "Static-Only", "Fixed"):
                for sev in ("Critical", "High", "Medium", "Low"):
                    exp = expected_counts[col].get(sev, 0)
                    act = summary_counts[col].get(sev, 0)
                    if exp != act:
                        count_mismatch.append(f"{sev}/{col}: report={act} findings={exp}")
            # 4. Parse per-severity finding tables for title + coverage
            report_rows = {}  # {fid: title_in_report}
            current_sev = None
            for line in report_text.splitlines():
                m = re.match(r"^###\s+(Critical|High|Medium|Low)\s*$", line.strip())
                if m:
                    current_sev = m.group(1)
                    continue
                if current_sev and line.strip().startswith("|"):
                    cells = [c.strip() for c in line.strip().strip("|").split("|")]
                    if len(cells) >= 2 and re.match(r"^RT-\d{3}$", cells[0]):
                        report_rows[cells[0]] = cells[1]
            # 5. Title reconciliation (exact match against frontmatter title)
            title_mismatch = []
            for fid, fd in findings.items():
                if fid in report_rows and report_rows[fid] != fd["fm"].get("title", ""):
                    title_mismatch.append(f"{fid}: REPORT='{report_rows[fid]}' vs finding='{fd['fm'].get('title', '')}'")
            # 6. Coverage — Open/Fixed/Remediated findings must appear in a severity table.
            #    FP findings may appear or not — not enforced.
            covered_ids = {fid for fid, fd in findings.items() if fd["fm"].get("status") in ("Open", "Fixed", "Remediated")}
            missing = covered_ids - set(report_rows.keys())
            extra = set(report_rows.keys()) - set(findings.keys())
            # 7. Emit
            msgs = []
            if count_mismatch:
                msgs.append(f"severity counts diverge: {count_mismatch}")
            if title_mismatch:
                msgs.append(f"titles diverge: {title_mismatch[:5]}")
            if missing:
                msgs.append(f"Open/Fixed findings missing from REPORT tables: {sorted(missing)}")
            if extra:
                msgs.append(f"REPORT has unknown finding IDs: {sorted(extra)}")
            # 8. Header presence (soft warning)
            header_missing = []
            for h in ("**Probe Date:**", "**Target:**", "**Skill Version:**", "**Method:**"):
                if h not in report_text:
                    header_missing.append(h)
            if header_missing:
                self.emit("G5.2", "WARN", f"REPORT.md missing header fields: {header_missing}")
            if msgs:
                self.emit("G5.2", "FAIL", "; ".join(msgs))
            elif not header_missing:
                self.emit("G5.2", "PASS", f"REPORT.md reconciles with {len(findings)} findings (counts + titles + coverage)")
        elif report_text is None:
            self.emit("G5.2", "FAIL", "REPORT.md not found")

        # G5.3 — config.yaml has schema_version and skill_version
        config_text = read(self.rt / "config.yaml")
        if config_text:
            if "schema_version" not in config_text:
                self.emit("G5.3", "FAIL", "config.yaml missing schema_version")
            if "skill_version" not in config_text:
                self.emit("G5.3", "FAIL", "config.yaml missing skill_version")
            if "schema_version" in config_text and "skill_version" in config_text:
                self.emit("G5.3", "PASS", "config.yaml has schema_version and skill_version")
        else:
            self.emit("G5.3", "FAIL", "config.yaml not found")

        # G5.4 — probe-date consistency across REPORT.md, surface.md, threat-model.md
        DATE_RE = re.compile(r"(?:\*\*)?(?:Probe date|probe_date|Date):(?:\*\*)?\s*(\d{4}-\d{2}-\d{2})")
        dates_found = {}
        for fname in ("REPORT.md", "surface.md", "threat-model.md"):
            fpath = self.rt / fname
            if fpath.exists():
                text = read(fpath)
                if text:
                    m = DATE_RE.search(text)
                    if m:
                        dates_found[fname] = m.group(1)
        if len(set(dates_found.values())) > 1:
            self.emit("G5.4", "WARN",
                      f"Probe dates diverge across reports: {dates_found}",
                      expected="single date across all", actual=dates_found)
        elif len(dates_found) >= 2:
            self.emit("G5.4", "PASS",
                      f"Probe date consistent: {list(dates_found.values())[0]} ({len(dates_found)} files)")

        # G5.6 — surface.md has content structure. The file must carry a markdown
        # heading and at least one endpoint-ish line (table row or path list).
        # surface.md is the foundation for later re-verification — an empty or
        # placeholder file is a structural failure, not just a warning.
        surface_text = read(self.rt / "surface.md")
        if surface_text is None:
            self.emit("G5.6", "FAIL", "surface.md not found")
        else:
            has_heading = bool(re.search(r"^#\s+", surface_text, re.MULTILINE))
            has_table_row = bool(re.search(r"^\s*\|.*\|.*\|", surface_text, re.MULTILINE))
            has_path_list = bool(re.search(r"^\s*[-*]\s+`?/?[A-Za-z]", surface_text, re.MULTILINE))
            path_count = len(re.findall(r"/[a-z0-9_/\-{:}]+", surface_text, re.IGNORECASE))
            if not has_heading:
                self.emit("G5.6", "FAIL", "surface.md missing top-level heading")
            elif not has_table_row and not has_path_list:
                self.emit("G5.6", "FAIL", "surface.md has no endpoint table or path list")
            elif path_count < 1:
                self.emit("G5.6", "FAIL", "surface.md has no recognizable endpoint paths")
            else:
                self.emit("G5.6", "PASS", f"surface.md has structure ({path_count} path references)")

        # G5.7 — threat-model.md covers every category used in findings (WARN).
        # A threat model may legitimately be narrower than the full findings
        # inventory, but a category used by findings with no matching threat row
        # is worth flagging.
        finding_categories = {fd["fm"].get("category", "") for fd in self._findings().values() if fd["fm"].get("category")}
        tm_lower = (tm_text or "").lower()
        missing_categories = sorted(c for c in finding_categories if c.lower() not in tm_lower)
        if missing_categories:
            self.emit("G5.7", "WARN",
                      f"threat-model.md missing categories used in findings: {missing_categories}")
        else:
            self.emit("G5.7", "PASS",
                      f"threat-model.md covers all {len(finding_categories)} finding categories")

        # G5.8 — attack-chain integrity (WARN; silent when no chains exist).
        # Findings' flat `chain:` key must resolve to a real chains/CH-NNN.md,
        # and every RT-id in a chain doc's `links:` must exist in findings/.
        findings = self._findings()
        finding_ids = set(findings.keys())
        chains_dir = self.rt / "chains"
        chain_refs = sorted({
            v for fd in findings.values()
            if (v := fd["fm"].get("chain"))
        })
        problems = []
        if chain_refs or chains_dir.exists():
            for ch in chain_refs:
                ch_file = chains_dir / f"{ch}.md"
                if not ch_file.exists():
                    problems.append(f"{ch}: referenced by findings but chains/{ch}.md missing")
            if chains_dir.exists():
                for ch_file in sorted(chains_dir.glob("CH-*.md")):
                    ch_id = ch_file.stem
                    ch_fm = parse_frontmatter(read(ch_file) or "") or {}
                    ch_links = ch_fm.get("links")
                    for link in ch_links if isinstance(ch_links, list) else []:
                        link = str(link).strip()
                        if link and link not in finding_ids:
                            problems.append(f"{ch_id}: links reference unknown finding {link}")
        if problems:
            self.emit("G5.8", "WARN",
                      f"attack-chain integrity: {problems[:5]}"
                      + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""))
        elif chain_refs or chains_dir.exists():
            n_docs = len(list(chains_dir.glob('CH-*.md')))
            self.emit("G5.8", "PASS",
                      f"{n_docs} chain doc(s); all chain: refs resolve and links point at real findings")

        self.emit("G5", "PASS", "Threat model & surface hygiene checks complete")

    # ── Main ────────────────────────────────────────────────────────────

    def run(self):
        if not self.rt.exists():
            self.emit("G0", "FAIL", f"No .red-team/ directory found in {self.target}")
            return self.report()

        self._check_g1()
        self._check_g2()
        self._check_g3()
        self._check_g4()
        self._check_g5()

        return self.report()

    def report(self):
        passed = sum(1 for c in self.checks if c["severity"] == "PASS")
        warned = sum(1 for c in self.checks if c["severity"] == "WARN")
        failed = sum(1 for c in self.checks if c["severity"] == "FAIL")
        auto_fix_candidates = [c["id"] for c in self.checks if c["severity"] in ("FAIL", "WARN")]
        report = {
            "target": str(self.rt),
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "schema_version_required": SCHEMA_VERSION_REQUIRED,
            "summary": {"passed": passed, "warned": warned, "failed": failed, "total": len(self.checks)},
            "checks": self.checks,
            "auto_fix_candidates": auto_fix_candidates,
        }
        return report


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Paladin-probe grader")
    parser.add_argument("target", help="Project root directory containing .red-team/")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Include PASS lines")
    args = parser.parse_args()

    grader = Grader(args.target, verbose=args.verbose)
    report = grader.run()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"\n{'='*60}")
        print(f"GRADER SUMMARY")
        print(f"{'='*60}")
        print(f"  Passed: {s['passed']}/{s['total']}")
        print(f"  Warned: {s['warned']}")
        print(f"  Failed: {s['failed']}/{s['total']}")
        if s["failed"] > 0 or s["warned"] > 0:
            print(f"  Auto-fix candidates: {len(report['auto_fix_candidates'])}")

    sys.exit(0 if report["summary"]["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
