# NVD-EPSS Parser

Pulls CVE records from the **NVD CVE API 2.0**, joins them against the daily **EPSS** (Exploit Prediction Scoring System) scores, and produces a single ranked table of vulnerabilities ordered by real-world exploitation probability.

Severity alone (CVSS) tells you how bad a vulnerability would be if exploited. EPSS tells you how likely it is to actually be exploited in the next 30 days. This tool puts both on the same row so triage decisions can be made on evidence rather than severity labels.

## What it does

| Stage | Function | Behaviour |
|---|---|---|
| Fetch CVEs | `fetch_nvd_cves()` | Queries the NVD CVE API 2.0 for a publication-date window of any length, splitting long ranges into windows of at most 90 days. Handles pagination (`startIndex` / `resultsPerPage`, max 2000/page), respects NVD's rolling rate limit — sleeping 0.6s per page with an API key, 6s without — and retries temporary failures. |
| Flatten | `parse_nvd_cves()` / `_extract_cvss()` | Converts deeply-nested CVE JSON into a flat DataFrame. Resolves the English description and picks the best available CVSS metric in preference order **v3.1 → v3.0 → v2**, extracting version, base score, severity, and vector string. |
| Fetch EPSS | `fetch_epss_scores()` | Downloads the gzipped daily EPSS CSV, decompressing it in memory. Publishing lags are handled by stepping backwards day-by-day (default 5 days) until a file is found; the date actually used is stamped on `df.attrs["score_date"]`. Any failure other than a missing file stops the run. |
| Join & rank | `join_and_rank()` | Left-joins NVD to EPSS on CVE ID and sorts descending by EPSS score, breaking ties by percentile and then CVE ID. |
| Export | `export_csv()` | Writes `nvd_epss_joined_YYYY-MM-DD.csv`. |

`run_pipeline()` runs the five stages in order and reports the match rate.

Output columns: `cve_id`, `published`, `last_modified`, `description`, `cvss_version`, `base_score`, `base_severity`, `vector_string`, `epss`, `percentile`.

Reading the output:

- There is one row per CVE published in the window, including CVEs NVD has marked as rejected.
- `epss` and `percentile` are blank when EPSS has not scored the CVE yet. These rows sort last.
- The four CVSS columns are blank when NVD has no v3.1, v3.0 or v2 score for the CVE. CVSS v4.0 scores are not read.
- A CVSS version can list scores from several sources. The first one listed is used, which is not always NVD's own.

## Requirements

- Python 3.10+ (the code uses `str | None` union syntax)
- `pandas` and `requests`
- Jupyter, only if you want to run the notebook

```bash
pip install -r requirements.txt
pip install jupyter                       # Optional, for the notebook
```

Tested on Python 3.13 with pandas 2.3 and 3.1.

### Optional: NVD API key

Unauthenticated requests are limited to 5 per 30 seconds. A [free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises this to 50 per 30 seconds and cuts the inter-page sleep from 6s to 0.6s. Set it as an environment variable before running the script or launching Jupyter:

```bash
export NVD_API_KEY="your-key-here"        # macOS / Linux
setx NVD_API_KEY "your-key-here"          # Windows (takes effect in new terminals)
```

The pipeline runs fine without one — just slower on large date windows.

## Usage

### Command line

```bash
python nvd_epss_parser.py                      # CVEs published in the last 7 days
python nvd_epss_parser.py --days 30            # Widen the window
python nvd_epss_parser.py --as-of 2026-07-30   # Re-create the run for a past date
```

By default it pulls CVEs published in the **last 7 days** and joins them against the most recent EPSS file.

| Option | Default | Meaning |
|---|---|---|
| `--days N` | `7` | Length of the publication window. Ranges over 90 days are split automatically. |
| `--as-of YYYY-MM-DD` | today | Date to treat as today. It ends the window, names the output file, and sets the EPSS date to the day before. |
| `--output-dir DIR` | current folder | Where to write the CSV. |
| `--epss-lookback DAYS` | `5` | How many days to search for an EPSS file. |

`--as-of` recovers a past date's CVE list and EPSS scores, but the NVD columns show each record as it is today, because the API only serves current data.

A run looks like this:

```
This product uses data from the NVD API but is not endorsed or certified by the NVD.
Fetching CVEs published 2026-11-01 to 2026-11-08 from NVD...
NVD CVEs fetched: 3352
EPSS score date used: 2026-11-07 (401675 rows)
Matched 2952/3352 NVD CVEs to an EPSS score (88.1%)
Wrote 3352 rows to nvd_epss_joined_2026-11-08.csv

Top 10 by EPSS:
         cve_id  base_score base_severity    epss  percentile
 CVE-2026-77690         8.8          HIGH 0.15584     0.96856
CVE-2026-121943         4.8        MEDIUM 0.05551     0.92893
CVE-2026-119742         7.2          HIGH 0.04088     0.90788
...
```

The exit code is 0 on success and 1 on failure, with a one-line error message, so a scheduler can detect a failed run.

### In your own code

```python
import datetime as dt

from nvd_epss_parser import fetch_epss_scores, fetch_nvd_cves, join_and_rank, parse_nvd_cves

today = dt.date.today()
raw_cves = fetch_nvd_cves(
    pub_start_date=dt.datetime.combine(today - dt.timedelta(days=30), dt.time.min),
    pub_end_date=dt.datetime.combine(today, dt.time.min),
)
ranked = join_and_rank(parse_nvd_cves(raw_cves), fetch_epss_scores(today - dt.timedelta(days=1)))
print(ranked[["cve_id", "base_score", "epss"]].head())
```

### Notebook

Open `parser.ipynb` and run all cells for the same pipeline in a notebook. To widen the window, change the `pub_start_date` argument in the pipeline cell:

```python
raw_cves = fetch_nvd_cves(
    pub_start_date=dt.datetime.combine(today - dt.timedelta(days=30), dt.time.min),
    pub_end_date=dt.datetime.combine(today, dt.time.min),
    api_key=NVD_API_KEY,
)
```

The notebook keeps its own copy of the functions and does not include the [changes listed below](#changes-from-the-original-notebook). The NVD API caps any single date range at 120 days, so backfills from the notebook should still be issued in ≤90-day chunks.

## Tests

```bash
pip install pytest
pytest
```

The tests run offline. They include golden-file tests that rebuild each sample CSV from its own data and check that the pipeline reproduces every line byte for byte.

## Why this is useful

- **Prioritisation that reflects reality.** A CVSS 10.0 with an EPSS of 0.0004 is a lower operational priority than a CVSS 7.5 with an EPSS of 0.20. The joined table makes that inversion visible immediately.
- **Cuts triage volume.** EPSS scores are heavily skewed — the vast majority of CVEs sit in the low-probability tail. Sorting by EPSS surfaces the small subset actually worth same-day attention.
- **Two authoritative sources, one table.** No manual cross-referencing between the NVD portal and EPSS lookups.
- **Reproducible and dated.** Every run writes a date-stamped CSV in a fully repeatable row order, so score movement over time can be tracked by diffing exports.
- **Portable output.** Plain CSV feeds directly into spreadsheets, BI tools, ticketing imports, or downstream detection/agentic pipelines.
- **Composable functions.** `fetch_nvd_cves`, `parse_nvd_cves`, `fetch_epss_scores`, and `join_and_rank` can be imported into a scheduled job or service.

## Data sources

- [NVD CVE API 2.0](https://nvd.nist.gov/vuln/data-feeds#APIS) — NIST's preferred access method; the legacy year-based JSON feed files are the fallback.
- [`empiricalsec/epss_scores`](https://github.com/empiricalsec/epss_scores) — daily EPSS score mirror, published as `cve,epss,percentile` gzipped CSVs.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Changes from the original notebook

`nvd_epss_parser.py` is a command-line version of the pipeline in `parser.ipynb`. The notebook itself is unchanged.

| Change | Why |
|---|---|
| Date ranges of any length work. Long ranges are split into windows of at most 90 days, and CVEs on a window boundary are de-duplicated. | NVD rejects a range over 120 days, and includes both ends of a range, so a boundary CVE would otherwise appear twice. |
| Temporary failures are retried, waiting 5, 10, 20, then 40 seconds: HTTP 403, 429 and 5xx, dropped connections and timeouts. The request timeout rose from 30 to 60 seconds. | One failed request used to lose an entire multi-page fetch. Some NVD pages took over 20 seconds in testing. |
| Pagination advances by the number of records received, and an empty page in mid-results is an error. | If NVD ever returned a short page, stepping by the page size would silently skip records. |
| The EPSS look-back only steps back on a 404. Any other failure stops the run. | A server error used to fall back to an older file silently, giving stale scores that looked current. |
| EPSS ties are sorted by percentile, then CVE ID. | The order is now fully repeatable, so exports diff cleanly. Row contents are unaffected, but tied rows can appear in a different order from the sample files. |
| A window with no CVEs writes a header-only CSV. | The notebook code crashes on an empty result. |
| NVD's explanation of a rejected request is included in the error message. | NVD puts the reason in a response header, which `raise_for_status()` does not show. |
| NVD's attribution notice is displayed. | [NVD asks](https://nvd.nist.gov/developers/start-here) applications that use its API to show it. |

Function names and arguments from the notebook, the output columns, the file naming, the date window and the CVSS preference order are unchanged.

To confirm this, on 2026-11-08 the notebook's code and this script were run on the same live data. All 3,352 rows were byte-identical, and only rows tied on EPSS changed order. Regenerating both sample CSVs from the live APIs gave the same CVE sets and identical EPSS values, and every row NVD has not modified since July came out identical.

## Repository contents

```
nvd_epss_parser.py                Pipeline script (fetch → parse → join → export)
parser.ipynb                      Original pipeline notebook
tests/test_nvd_epss_parser.py     Offline test suite
requirements.txt                  Runtime dependencies
pytest.ini                        Test configuration
nvd_epss_joined_2026-07-29.csv    Sample output
nvd_epss_joined_2026-07-30.csv    Sample output
```
