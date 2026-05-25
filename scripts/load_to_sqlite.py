#!/usr/bin/env python3
"""
load_to_sqlite.py
-----------------
Reads TruffleHog JSONL output files (github + docker scans) and
loads every finding into a SQLite database that Redash can query.

Usage:
    python load_to_sqlite.py \
        --github  scan_results/github_scan.jsonl \
        --docker  scan_results/docker_scan.jsonl \
        --db      scan_results/trufflehog.db
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Schema ────────────────────────────────────────────────────────────────────

CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_source         TEXT NOT NULL,          -- 'github' | 'docker'
    scanned_at          TEXT NOT NULL,          -- ISO-8601 UTC timestamp
    detector_name       TEXT,
    detector_type       INTEGER,
    decoder_name        TEXT,
    verified            INTEGER DEFAULT 0,      -- 0/1 boolean
    raw                 TEXT,                   -- redacted raw secret
    raw_v2              TEXT,
    source_name         TEXT,
    source_type         INTEGER,
    source_metadata_str TEXT,                   -- JSON blob
    repository_url      TEXT,
    "commit"            TEXT,
    file                TEXT,
    email               TEXT,
    "timestamp"         TEXT,
    line                INTEGER,
    link                TEXT,
    extra_data_str      TEXT                    -- JSON blob
);
"""

CREATE_SUMMARY = """
CREATE TABLE IF NOT EXISTS scan_summary (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at      TEXT NOT NULL,
    scan_source     TEXT NOT NULL,
    total_findings  INTEGER DEFAULT 0,
    verified_count  INTEGER DEFAULT 0,
    unverified_count INTEGER DEFAULT 0,
    detector_list   TEXT    -- comma-separated
);
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_findings_source   ON findings(scan_source);",
    "CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector_name);",
    "CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);",
    "CREATE INDEX IF NOT EXISTS idx_findings_file     ON findings(file);",
    "CREATE INDEX IF NOT EXISTS idx_findings_repo     ON findings(repository_url);",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _str(obj) -> str | None:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return json.dumps(obj)
    return str(obj)


def _int(obj) -> int | None:
    try:
        return int(obj)
    except (TypeError, ValueError):
        return None


def parse_finding(raw_line: str, scan_source: str, scanned_at: str) -> dict | None:
    """Parse one JSONL line from TruffleHog into a flat dict."""
    line = raw_line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        print(f"  [WARN] Could not parse line: {e}", file=sys.stderr)
        return None

    # TruffleHog v3 JSON shape:
    # {
    #   "SourceMetadata": { "Data": { "Git": { "commit": ..., "file": ..., ... } } },
    #   "SourceID":  1,
    #   "SourceType": 2,
    #   "SourceName": "trufflehog - git",
    #   "DetectorType": 17,
    #   "DetectorName": "AWS",
    #   "DecoderName": "BASE64",
    #   "Verified": true,
    #   "Raw": "AKIA...",
    #   "RawV2": "...",
    #   "Redacted": "...",
    #   "ExtraData": { ... },
    #   "StructuredData": null
    # }

    source_meta = obj.get("SourceMetadata") or {}
    data_block  = source_meta.get("Data") or {}

    # Flatten the first key inside Data (Git, S3, Filesystem, Docker, …)
    inner: dict = {}
    if data_block:
        inner = next(iter(data_block.values()), {}) or {}

    return {
        "scan_source":         scan_source,
        "scanned_at":          scanned_at,
        "detector_name":       obj.get("DetectorName"),
        "detector_type":       _int(obj.get("DetectorType")),
        "decoder_name":        obj.get("DecoderName"),
        "verified":            1 if obj.get("Verified") else 0,
        "raw":                 obj.get("Redacted") or obj.get("Raw"),   # prefer redacted
        "raw_v2":              obj.get("RawV2"),
        "source_name":         obj.get("SourceName"),
        "source_type":         _int(obj.get("SourceType")),
        "source_metadata_str": _str(source_meta),
        "repository_url":      inner.get("repository") or inner.get("remote"),
        "commit":              inner.get("commit"),
        "file":                inner.get("file"),
        "email":               inner.get("email"),
        "timestamp":           inner.get("timestamp"),
        "line":                _int(inner.get("line")),
        "link":                inner.get("link"),
        "extra_data_str":      _str(obj.get("ExtraData")),
    }


def load_file(path: Path, scan_source: str, scanned_at: str, cur: sqlite3.Cursor) -> list[dict]:
    """Load all findings from a JSONL file and insert into DB. Returns list of dicts."""
    if not path.exists():
        print(f"  [SKIP] {path} not found", file=sys.stderr)
        return []

    findings = []
    with path.open() as fh:
        for line in fh:
            row = parse_finding(line, scan_source, scanned_at)
            if row:
                findings.append(row)

    if findings:
        cur.executemany(
            """INSERT INTO findings
               (scan_source, scanned_at, detector_name, detector_type, decoder_name,
                verified, raw, raw_v2, source_name, source_type, source_metadata_str,
                repository_url, "commit", file, email, "timestamp", line, link, extra_data_str)
               VALUES
               (:scan_source, :scanned_at, :detector_name, :detector_type, :decoder_name,
                :verified, :raw, :raw_v2, :source_name, :source_type, :source_metadata_str,
                :repository_url, :commit, :file, :email, :timestamp, :line, :link, :extra_data_str)
            """,
            findings,
        )
        print(f"  [OK] {path.name}: inserted {len(findings)} finding(s)")
    else:
        print(f"  [OK] {path.name}: no findings")

    return findings


def write_summary(findings: list[dict], scan_source: str, scanned_at: str, cur: sqlite3.Cursor):
    verified   = sum(1 for f in findings if f["verified"])
    detectors  = sorted({f["detector_name"] for f in findings if f["detector_name"]})
    cur.execute(
        """INSERT INTO scan_summary
           (scanned_at, scan_source, total_findings, verified_count, unverified_count, detector_list)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scanned_at, scan_source, len(findings), verified, len(findings) - verified,
         ", ".join(detectors)),
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Load TruffleHog results into SQLite")
    parser.add_argument("--github", type=Path, default=Path("scan_results/github_scan.jsonl"))
    parser.add_argument("--docker", type=Path, default=Path("scan_results/docker_scan.jsonl"))
    parser.add_argument("--db",     type=Path, default=Path("scan_results/trufflehog.db"))
    args = parser.parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(args.db)
    cur = con.cursor()

    # Create schema
    cur.execute(CREATE_FINDINGS)
    cur.execute(CREATE_SUMMARY)
    for idx in INDEXES:
        cur.execute(idx)
    con.commit()

    scanned_at = now_utc()

    print(f"\nLoading findings into {args.db}  [{scanned_at}]")

    github_findings = load_file(args.github, "github", scanned_at, cur)
    docker_findings = load_file(args.docker, "docker", scanned_at, cur)

    write_summary(github_findings, "github", scanned_at, cur)
    write_summary(docker_findings, "docker", scanned_at, cur)

    con.commit()
    con.close()

    total = len(github_findings) + len(docker_findings)
    print(f"\nDone. Total findings stored: {total}")
    print(f"DB path: {args.db.resolve()}\n")


if __name__ == "__main__":
    main()
