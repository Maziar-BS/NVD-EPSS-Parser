# NVD-EPSS Parser

Pulls CVE records from the **NVD CVE API 2.0**, joins them against the daily **EPSS** (Exploit Prediction Scoring System) scores, and produces a single ranked table of vulnerabilities ordered by real-world exploitation probability.

Severity alone (CVSS) tells you how bad a vulnerability would be if exploited. EPSS tells you how likely it is to actually be exploited in the next 30 days. This tool puts both on the same row so triage decisions can be made on evidence rather than severity labels.

## What it does

| Stage | Function | Behaviour |
|---|---|---|
| Fetch CVEs | `fetch_nvd_cves()` | Queries the NVD CVE API 2.0 for a publication-date window. Handles pagination (`startIndex` / `resultsPerPage`, max 2000/page) and respects NVD's rolling rate limit — sleeping 0.6s per page with an API key, 6s without. |
| Flatten | `parse_nvd_cves()` / `_extract_cvss()` | Converts deeply-nested CVE JSON into a flat DataFrame. Resolves the English description and picks the best available CVSS metric in preference order **v3.1 → v3.0 → v2**, extracting version, base score, severity, and vector string. |
| Fetch EPSS | `fetch_epss_scores()` | Downloads the gzipped daily EPSS CSV, decompressing it in memory. Publishing lags are handled by stepping backwards day-by-day (default 5 days) until a file is found; the date actually used is stamped on `df.attrs["score_date"]`. |
| Join & rank | pipeline cells | Left-joins NVD to EPSS on CVE ID, reports the match rate, and sorts descending by EPSS score. |
| Export | pipeline cells | Writes `nvd_epss_joined_YYYY-MM-DD.csv`. |

Output columns: `cve_id`, `published`, `last_modified`, `description`, `cvss_version`, `base_score`, `base_severity`, `vector_string`, `epss`, `percentile`.

## Requirements

- Python 3.10+ (the code uses `str | None` union syntax)
- `pandas`, `requests`, and a Jupyter environment

```bash
pip install pandas requests jupyter
```

### Optional: NVD API key

Unauthenticated requests are limited to 5 per 30 seconds. A [free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises this to 50 per 30 seconds and cuts the inter-page sleep from 6s to 0.6s. Set it as an environment variable before launching Jupyter:

```bash
export NVD_API_KEY="your-key-here"        # macOS / Linux
setx NVD_API_KEY "your-key-here"          # Windows
```

The pipeline runs fine without one — just slower on large date windows.

## Usage

Open `parser.ipynb` and run all cells. By default it pulls CVEs published in the **last 7 days** and joins them against the most recent EPSS file.

To widen the window, change the `pub_start_date` argument in the pipeline cell:

```python
raw_cves = fetch_nvd_cves(
    pub_start_date=dt.datetime.combine(today - dt.timedelta(days=30), dt.time.min),
    pub_end_date=dt.datetime.combine(today, dt.time.min),
    api_key=NVD_API_KEY,
)
```

The NVD API caps any single date range at 120 days, so historical backfills should be issued in ≤90-day chunks.

## Why this is useful

- **Prioritisation that reflects reality.** A CVSS 10.0 with an EPSS of 0.0004 is a lower operational priority than a CVSS 7.5 with an EPSS of 0.20. The joined table makes that inversion visible immediately.
- **Cuts triage volume.** EPSS scores are heavily skewed — the vast majority of CVEs sit in the low-probability tail. Sorting by EPSS surfaces the small subset actually worth same-day attention.
- **Two authoritative sources, one table.** No manual cross-referencing between the NVD portal and EPSS lookups.
- **Reproducible and dated.** Every run writes a date-stamped CSV, so score movement over time can be tracked by diffing exports.
- **Portable output.** Plain CSV feeds directly into spreadsheets, BI tools, ticketing imports, or downstream detection/agentic pipelines.
- **Composable functions.** `fetch_nvd_cves`, `parse_nvd_cves`, and `fetch_epss_scores` are self-contained and can be lifted out of the notebook into a scheduled script or service with no changes.

## Data sources

- [NVD CVE API 2.0](https://nvd.nist.gov/vuln/data-feeds#APIS) — NIST's preferred access method; the legacy year-based JSON feed files are the fallback.
- [`empiricalsec/epss_scores`](https://github.com/empiricalsec/epss_scores) — daily EPSS score mirror, published as `cve,epss,percentile` gzipped CSVs.

## Repository contents

```
parser.ipynb                      Pipeline notebook (fetch → parse → join → export)
nvd_epss_joined_2026-07-29.csv    Sample output
nvd_epss_joined_2026-07-30.csv    Sample output
```
