-- ============================================================
--  REDASH DASHBOARD QUERIES  –  TruffleHog Findings
--
--  Data source type : SQLite
--  DB path          : /data/trufflehog.db   (inside the container)
--  
--  Paste each numbered query into a separate Redash query,
--  then add the suggested visualization, and pin all of them
--  to a single dashboard called "TruffleHog – Secrets Scan".
-- ============================================================


-- ────────────────────────────────────────────────────────────
-- Q1 · COUNTER: Total findings (verified vs unverified)
--     Visualization → Counter  (value = total, target = 0)
-- ────────────────────────────────────────────────────────────
SELECT
    COUNT(*)                          AS total_findings,
    COALESCE(SUM(verified),    0)     AS verified,
    COUNT(*) - COALESCE(SUM(verified),0) AS unverified
FROM findings;


-- ────────────────────────────────────────────────────────────
-- Q2 · TABLE: All verified findings  (most critical)
--     Visualization → Table
-- ────────────────────────────────────────────────────────────
SELECT
    id,
    scan_source,
    detector_name,
    decoder_name,
    file,
    "commit",
    line,
    repository_url,
    link,
    scanned_at
FROM findings
WHERE verified = 1
ORDER BY scanned_at DESC;


-- ────────────────────────────────────────────────────────────
-- Q3 · BAR CHART: Findings by detector type
--     Visualization → Bar chart  (x = detector_name, y = count)
-- ────────────────────────────────────────────────────────────
SELECT
    COALESCE(detector_name, 'Unknown') AS detector_name,
    COUNT(*)                           AS total,
    SUM(verified)                      AS verified,
    COUNT(*) - SUM(verified)           AS unverified
FROM findings
GROUP BY detector_name
ORDER BY total DESC
LIMIT 20;


-- ────────────────────────────────────────────────────────────
-- Q4 · PIE CHART: Findings by scan source (github vs docker)
--     Visualization → Pie chart
-- ────────────────────────────────────────────────────────────
SELECT
    scan_source,
    COUNT(*) AS findings
FROM findings
GROUP BY scan_source;


-- ────────────────────────────────────────────────────────────
-- Q5 · BAR CHART: Top 10 files with most findings
--     Visualization → Horizontal bar chart
-- ────────────────────────────────────────────────────────────
SELECT
    COALESCE(file, '(unknown)') AS file_path,
    COUNT(*)                    AS findings,
    SUM(verified)               AS verified
FROM findings
WHERE file IS NOT NULL
GROUP BY file
ORDER BY findings DESC
LIMIT 10;


-- ────────────────────────────────────────────────────────────
-- Q6 · LINE / BAR CHART: Findings over time (by scan run)
--     Visualization → Line chart  (x = scanned_at, y = total)
-- ────────────────────────────────────────────────────────────
SELECT
    DATE(scanned_at)  AS scan_date,
    scan_source,
    COUNT(*)          AS total_findings,
    SUM(verified)     AS verified
FROM findings
GROUP BY DATE(scanned_at), scan_source
ORDER BY scan_date ASC;


-- ────────────────────────────────────────────────────────────
-- Q7 · TABLE: Scan history summary
--     Visualization → Table
-- ────────────────────────────────────────────────────────────
SELECT
    scanned_at,
    scan_source,
    total_findings,
    verified_count,
    unverified_count,
    detector_list
FROM scan_summary
ORDER BY scanned_at DESC;


-- ────────────────────────────────────────────────────────────
-- Q8 · TABLE: All findings (browsable, latest first)
--     Visualization → Table  (add filters: scan_source, verified)
-- ────────────────────────────────────────────────────────────
SELECT
    id,
    scan_source,
    verified,
    detector_name,
    decoder_name,
    file,
    line,
    "commit",
    repository_url,
    link,
    scanned_at
FROM findings
ORDER BY scanned_at DESC, verified DESC;
