#!/usr/bin/env python3
"""
print_summary.py
----------------
Prints a human-readable summary of the latest TruffleHog scan
stored in the SQLite database.  Used as the last step in CircleCI
so results are visible directly in the build log.
"""

import argparse
import sqlite3
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path("scan_results/trufflehog.db"))
    args = parser.parse_args()

    if not args.db.exists():
        print(f"DB not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # ── Overall totals ────────────────────────────────────────────────────────
    cur.execute("SELECT COUNT(*) AS total, SUM(verified) AS verified FROM findings")
    row = cur.fetchone()
    total    = row["total"]    or 0
    verified = row["verified"] or 0

    print("\n" + "=" * 60)
    print("  TRUFFLEHOG SCAN SUMMARY")
    print("=" * 60)
    print(f"  Total findings : {total}")
    print(f"  Verified       : {verified}")
    print(f"  Unverified     : {total - verified}")

    # ── Breakdown by source ───────────────────────────────────────────────────
    print("\n  By scan source:")
    cur.execute("""
        SELECT scan_source,
               COUNT(*)    AS total,
               SUM(verified) AS verified
        FROM   findings
        GROUP  BY scan_source
        ORDER  BY total DESC
    """)
    for r in cur.fetchall():
        print(f"    {r['scan_source']:10s}  total={r['total']}  verified={r['verified'] or 0}")

    # ── Top detectors ─────────────────────────────────────────────────────────
    print("\n  Top detectors (by finding count):")
    cur.execute("""
        SELECT detector_name,
               COUNT(*) AS cnt,
               SUM(verified) AS verified
        FROM   findings
        WHERE  detector_name IS NOT NULL
        GROUP  BY detector_name
        ORDER  BY cnt DESC
        LIMIT  15
    """)
    rows = cur.fetchall()
    if rows:
        for r in rows:
            print(f"    {r['detector_name']:30s}  {r['cnt']:4d}  "
                  f"(verified: {r['verified'] or 0})")
    else:
        print("    (none)")

    # ── Top files ────────────────────────────────────────────────────────────
    print("\n  Top files with most findings:")
    cur.execute("""
        SELECT file, COUNT(*) AS cnt
        FROM   findings
        WHERE  file IS NOT NULL
        GROUP  BY file
        ORDER  BY cnt DESC
        LIMIT  10
    """)
    rows = cur.fetchall()
    if rows:
        for r in rows:
            print(f"    {r['cnt']:4d}  {r['file']}")
    else:
        print("    (none)")

    print("=" * 60 + "\n")

    con.close()

    # Exit non-zero if verified secrets were found (useful for gating deploys)
    if verified > 0:
        print(f"⚠️  {verified} VERIFIED secret(s) found — review before merging!\n")
        sys.exit(1)


if __name__ == "__main__":
    main()