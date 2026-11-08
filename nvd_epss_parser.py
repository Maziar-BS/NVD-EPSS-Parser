#!/usr/bin/env python3
"""NVD-EPSS Parser: rank newly published CVEs by how likely they are to be exploited.

CVSS says how bad a vulnerability would be if exploited. EPSS says how likely it
is to be exploited in the next 30 days. This script puts both on one row, so triage
can follow evidence rather than severity labels alone.

The pipeline has five stages, and this file has one section per stage:

    1. Fetch CVEs    fetch_nvd_cves()      NVD CVE API 2.0, paginated and rate-limited
    2. Flatten       parse_nvd_cves()      nested CVE JSON -> one flat row per CVE
    3. Fetch EPSS    fetch_epss_scores()   daily gzipped CSV, tolerant of publishing lag
    4. Join & rank   join_and_rank()       left join on CVE ID, highest EPSS first
    5. Export        export_csv()          nvd_epss_joined_YYYY-MM-DD.csv

Usage:
    python nvd_epss_parser.py                      # CVEs published in the last 7 days
    python nvd_epss_parser.py --days 30            # widen the window
    python nvd_epss_parser.py --as-of 2026-07-30   # re-create the run for a past date

Set the NVD_API_KEY environment variable to use NVD's faster, authenticated rate limit.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import datetime as dt
import gzip
import io
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pandas as pd
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_RAW_BASE = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main"

# NVD asks every application that uses its API to display this notice.
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."

# NVD API limits (https://nvd.nist.gov/developers/start-here).
NVD_MAX_RESULTS_PER_PAGE = 2000  # Documented default and maximum page size.
NVD_MAX_WINDOW_DAYS = 90  # The API rejects date ranges over 120 days; stay well inside that.
NVD_SLEEP_WITH_KEY_S = 0.6  # 50 requests per rolling 30 s allows one every 0.6 s.
NVD_SLEEP_NO_KEY_S = 6.0  # 5 requests per rolling 30 s allows one every 6 s.
NVD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"  # With no offset, NVD reads these as UTC.

# How hard to try before treating a request as failed.
HTTP_TIMEOUT_S = 60  # NVD can take a while to assemble a full 2000-record page.
MAX_RETRIES = 4
RETRY_BACKOFF_S = 5.0  # Waits 5, 10, 20, then 40 s, which outlasts NVD's 30 s rate window.
# 403 is how NIST's firewall rejects clients over the rate limit. The others are the
# usual temporary failures. A 404 is deliberately absent: it is a definite answer.
RETRYABLE_STATUS_CODES = frozenset({403, 429, 500, 502, 503, 504})
RETRYABLE_ERRORS = (
    requests.ConnectionError,
    requests.Timeout,
    requests.exceptions.ChunkedEncodingError,  # Connection dropped mid-download.
)

# Defaults for a normal run.
DEFAULT_WINDOW_DAYS = 7
DEFAULT_EPSS_LOOKBACK_DAYS = 5

# Column order of the exported CSV. The sample files in this repository are the
# reference for this layout, so anything reading those files can read a new run.
NVD_COLUMNS = [
    "cve_id",
    "published",
    "last_modified",
    "description",
    "cvss_version",
    "base_score",
    "base_severity",
    "vector_string",
]
OUTPUT_COLUMNS = [*NVD_COLUMNS, "epss", "percentile"]


# ---------------------------------------------------------------------------
# HTTP helper (shared by stages 1 and 3)
# ---------------------------------------------------------------------------


def _get_with_retry(
    url: str, params: dict | None = None, headers: dict | None = None
) -> requests.Response:
    """GET ``url``, retrying temporary failures with exponential backoff.

    A multi-page fetch should not lose all its progress to one hiccup, so rate-limit
    responses, server errors, dropped connections and timeouts are all retried.

    Returns:
        The final response, whatever its status, so the caller decides what a status
        such as 404 means.

    Raises:
        requests.RequestException: The connection still fails after every retry.
    """
    attempt = 0
    while True:
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT_S)
            if resp.status_code not in RETRYABLE_STATUS_CODES or attempt == MAX_RETRIES:
                return resp
            problem = f"HTTP {resp.status_code}"
        except RETRYABLE_ERRORS as exc:
            if attempt == MAX_RETRIES:
                raise
            problem = type(exc).__name__

        # Double the wait after each failure to give the server room to recover.
        delay = RETRY_BACKOFF_S * 2**attempt
        attempt += 1
        print(
            f"{problem} from {url}; retry {attempt}/{MAX_RETRIES} in {delay:.0f}s",
            file=sys.stderr,
        )
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Stage 1: Fetch CVEs from the NVD CVE API 2.0
# ---------------------------------------------------------------------------


def _split_date_window(
    start: dt.datetime, end: dt.datetime, max_days: int = NVD_MAX_WINDOW_DAYS
) -> Iterator[tuple[dt.datetime, dt.datetime]]:
    """Cut ``start``..``end`` into back-to-back windows of at most ``max_days`` days.

    NVD rejects any single date range longer than 120 days, so a long backfill has
    to be requested as several shorter ranges.
    """
    step = dt.timedelta(days=max_days)
    while start < end:
        stop = min(start + step, end)
        yield start, stop
        start = stop


def _fetch_nvd_window(
    start: dt.datetime,
    end: dt.datetime,
    headers: dict,
    results_per_page: int,
    sleep_s: float,
) -> list[dict]:
    """Page through every CVE published in one date range that NVD will accept."""
    cves: list[dict] = []
    start_index = 0
    total_results = None  # Unknown until the first response arrives.

    while total_results is None or start_index < total_results:
        params = {
            "pubStartDate": start.strftime(NVD_DATE_FORMAT),
            "pubEndDate": end.strftime(NVD_DATE_FORMAT),
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        resp = _get_with_retry(NVD_API_BASE, params=params, headers=headers)
        if not resp.ok:
            # NVD explains rejected requests in a "message" response header (for
            # example "Date range cannot exceed 120 days."), so pass that on.
            detail = resp.headers.get("message") or resp.reason
            raise requests.HTTPError(
                f"NVD API returned HTTP {resp.status_code}: {detail}", response=resp
            )

        payload = resp.json()
        total_results = payload["totalResults"]
        # Each list item wraps the record we want under a "cve" key.
        page = [item["cve"] for item in payload.get("vulnerabilities", [])]
        cves.extend(page)

        # Advance by what actually arrived, not by what was requested, so a page
        # shorter than requested cannot silently skip records.
        start_index += len(page)
        if start_index < total_results:
            if not page:
                # Without this check, an empty page would repeat the same request forever.
                raise RuntimeError(
                    f"NVD returned an empty page at startIndex {start_index} "
                    f"of {total_results}; the result set is incomplete"
                )
            time.sleep(sleep_s)  # Stay under NVD's rate limit between pages.

    return cves


def fetch_nvd_cves(
    pub_start_date: dt.datetime,
    pub_end_date: dt.datetime,
    api_key: str | None = None,
    results_per_page: int = NVD_MAX_RESULTS_PER_PAGE,
) -> list[dict]:
    """Fetch raw CVE records from NVD for a publication date range of any length.

    Args:
        pub_start_date: Start of the range. Naive datetimes are read by NVD as UTC.
        pub_end_date: End of the range. NVD treats both ends as inclusive.
        api_key: Optional NVD API key. It raises the rate limit and shortens the
            sleep between requests from 6 s to 0.6 s.
        results_per_page: Page size to request (NVD's maximum is 2000).

    Returns:
        One unparsed CVE JSON object per CVE, in the order NVD returned them.

    Raises:
        ValueError: The range is empty or reversed.
        requests.RequestException: NVD rejects a request or cannot be reached.
        RuntimeError: NVD stops returning records before the end of the result set.
    """
    if pub_start_date >= pub_end_date:
        raise ValueError(f"Empty date range: {pub_start_date} to {pub_end_date}")

    # The key travels in a header, so it never appears in URLs, logs or error messages.
    headers = {"apiKey": api_key} if api_key else {}
    sleep_s = NVD_SLEEP_WITH_KEY_S if api_key else NVD_SLEEP_NO_KEY_S

    # Keyed by CVE ID because NVD includes both ends of a date range: a CVE published
    # exactly on the boundary between two windows comes back twice.
    cves_by_id: dict[str, dict] = {}
    windows = _split_date_window(pub_start_date, pub_end_date)
    for number, (start, end) in enumerate(windows):
        if number > 0:
            time.sleep(sleep_s)  # A new window is one more request to rate-limit.
        for cve in _fetch_nvd_window(start, end, headers, results_per_page, sleep_s):
            cves_by_id[cve["id"]] = cve

    return list(cves_by_id.values())


# ---------------------------------------------------------------------------
# Stage 2: Flatten the nested CVE JSON into a table
# ---------------------------------------------------------------------------


def _extract_cvss(metrics: dict) -> dict:
    """Pick the best CVSS metric from a CVE's ``metrics`` block.

    NVD may publish several CVSS versions for one CVE. The preference order is
    v3.1, then v3.0, then v2. A version can also list several entries, one per scoring
    source (NVD itself or the CVE's assigner). The first entry is used, whichever
    source it came from.

    Returns:
        A dict with keys cvss_version, base_score, base_severity and vector_string.
        All four are None when the CVE has no score in any of those versions, which
        is common for new CVEs that NVD has not analysed yet.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return {
                "cvss_version": data.get("version"),
                "base_score": data.get("baseScore"),
                # v2 keeps baseSeverity beside cvssData; v3.x keeps it inside cvssData.
                "base_severity": entries[0].get("baseSeverity", data.get("baseSeverity")),
                "vector_string": data.get("vectorString"),
            }
    return {"cvss_version": None, "base_score": None, "base_severity": None, "vector_string": None}


def parse_nvd_cves(raw_cves: list[dict]) -> pd.DataFrame:
    """Flatten raw NVD CVE records into a DataFrame with one row per CVE.

    Args:
        raw_cves: CVE objects as returned by fetch_nvd_cves().

    Returns:
        A DataFrame with the columns in NVD_COLUMNS, including when there are no CVEs.
    """
    rows = []
    for cve in raw_cves:
        # NVD stores descriptions in several languages, so find the English one.
        en_desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        rows.append(
            {
                "cve_id": cve["id"],
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": en_desc,
                **_extract_cvss(cve.get("metrics", {})),
            }
        )
    # Naming the columns keeps the later merge working when a quiet window has no CVEs.
    return pd.DataFrame(rows, columns=NVD_COLUMNS)


# ---------------------------------------------------------------------------
# Stage 3: Fetch the daily EPSS scores
# ---------------------------------------------------------------------------


def fetch_epss_scores(
    date: dt.date, max_lookback_days: int = DEFAULT_EPSS_LOOKBACK_DAYS
) -> pd.DataFrame:
    """Download the EPSS scores for ``date``, or the nearest earlier day available.

    Files are published daily, sometimes late, so a missing file (404) means "try the
    day before". Any other failure is raised instead: quietly falling back to an
    older file during an outage would produce stale scores that look current.

    Args:
        date: The preferred score date.
        max_lookback_days: How many days to try, counting ``date`` itself.

    Returns:
        A DataFrame with columns cve, epss and percentile. The date actually used is
        stamped on ``df.attrs["score_date"]`` as an ISO string.

    Raises:
        FileNotFoundError: No file exists anywhere in the look-back range.
        requests.RequestException: The download fails for a reason other than 404.
        ValueError: The file does not have the expected columns.
    """
    for offset in range(max_lookback_days):
        day = date - dt.timedelta(days=offset)
        url = f"{EPSS_RAW_BASE}/{day.year}/epss_scores-{day.isoformat()}.csv.gz"
        resp = _get_with_retry(url)
        if resp.status_code == 404:
            continue  # Not published yet: step back one day.
        resp.raise_for_status()

        # Decompress in memory. The file opens with a "#model_version:...,score_date:..."
        # line, and comment="#" lets pandas skip it and find the real header below.
        with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
            df = pd.read_csv(f, comment="#")

        # Fail clearly here rather than with a confusing merge error in the next stage.
        missing = {"cve", "epss", "percentile"} - set(df.columns)
        if missing:
            raise ValueError(f"EPSS file {url} is missing columns: {sorted(missing)}")

        df.attrs["score_date"] = day.isoformat()
        return df

    raise FileNotFoundError(
        f"No EPSS scores file found in the {max_lookback_days} days up to {date.isoformat()}"
    )


# ---------------------------------------------------------------------------
# Stage 4: Join NVD to EPSS and rank by exploitation probability
# ---------------------------------------------------------------------------


def join_and_rank(nvd_df: pd.DataFrame, epss_df: pd.DataFrame) -> pd.DataFrame:
    """Attach EPSS scores to the NVD rows and sort the riskiest CVEs to the top.

    Args:
        nvd_df: Output of parse_nvd_cves().
        epss_df: Output of fetch_epss_scores().

    Returns:
        A DataFrame with the columns in OUTPUT_COLUMNS, one row per NVD row.
    """
    # how="left" keeps every NVD row. Brand-new CVEs often have no EPSS score yet, and
    # they should stay visible with a blank score rather than disappear from the table.
    # validate= raises an error if EPSS ever lists a CVE twice, instead of silently
    # duplicating rows.
    joined = nvd_df.merge(
        epss_df[["cve", "epss", "percentile"]],
        left_on="cve_id",
        right_on="cve",
        how="left",
        validate="many_to_one",
    ).drop(columns="cve")

    # EPSS values are rounded, so many CVEs tie, but percentile still separates most of
    # them. CVE ID settles whatever is left, making the order fully repeatable so that
    # two exports can be diffed. Unscored CVEs (NaN) go last.
    return joined.sort_values(
        by=["epss", "percentile", "cve_id"],
        ascending=[False, False, True],
        na_position="last",
        ignore_index=True,
    )[OUTPUT_COLUMNS]


# ---------------------------------------------------------------------------
# Stage 5: Export the ranked table to a dated CSV
# ---------------------------------------------------------------------------


def export_csv(joined: pd.DataFrame, as_of: dt.date, output_dir: Path = Path(".")) -> Path:
    """Write ``nvd_epss_joined_YYYY-MM-DD.csv`` and return its path.

    The date in the file name is what makes score movement trackable: each run leaves
    its own file, and any two can be diffed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"nvd_epss_joined_{as_of.isoformat()}.csv"
    # Descriptions can contain non-ASCII text and line breaks. The csv writer quotes the
    # line breaks, and naming the encoding keeps the text intact on every platform. Rows
    # end with the platform's own line ending, which is CRLF in the Windows-made samples.
    joined.to_csv(output_path, index=False, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Pipeline: run all five stages in order
# ---------------------------------------------------------------------------


def run_pipeline(
    as_of: dt.date,
    days: int = DEFAULT_WINDOW_DAYS,
    api_key: str | None = None,
    output_dir: Path = Path("."),
    epss_lookback_days: int = DEFAULT_EPSS_LOOKBACK_DAYS,
) -> pd.DataFrame:
    """Fetch, flatten, join, rank and export, printing a summary along the way.

    Args:
        as_of: The date to treat as "today". It names the output file, ends the CVE
            window, and sets the EPSS score date to the day before. For a past date the
            EPSS scores are historical but the NVD columns are current, because NVD only
            serves the latest version of each record.
        days: Length of the CVE publication window, in days.
        api_key: Optional NVD API key.
        output_dir: Folder for the CSV. Created if it does not exist.
        epss_lookback_days: How many days to search for an EPSS file.

    Returns:
        The joined and ranked table that was written to the CSV.
    """
    # The window covers whole days and stops at the midnight that starts as_of.
    window_end = dt.datetime.combine(as_of, dt.time.min)
    window_start = window_end - dt.timedelta(days=days)

    # Stages 1 and 2: NVD.
    print(f"Fetching CVEs published {window_start:%Y-%m-%d} to {window_end:%Y-%m-%d} from NVD...")
    raw_cves = fetch_nvd_cves(window_start, window_end, api_key=api_key)
    nvd_df = parse_nvd_cves(raw_cves)
    print(f"NVD CVEs fetched: {len(nvd_df)}")

    # Stage 3: EPSS. Start from the day before as_of, because the file for the current
    # day is usually not published yet.
    epss_df = fetch_epss_scores(as_of - dt.timedelta(days=1), max_lookback_days=epss_lookback_days)
    print(f"EPSS score date used: {epss_df.attrs['score_date']} ({len(epss_df)} rows)")

    # Stage 4: join and rank, then report how much of the table has a score.
    joined = join_and_rank(nvd_df, epss_df)
    matched = joined["epss"].notna().sum()
    match_rate = f"{matched / len(joined):.1%}" if len(joined) else "n/a"
    print(f"Matched {matched}/{len(joined)} NVD CVEs to an EPSS score ({match_rate})")

    # Stage 5: export.
    output_path = export_csv(joined, as_of, output_dir)
    print(f"Wrote {len(joined)} rows to {output_path}")

    # Show the top of the ranking, leaving out the long description column.
    if len(joined):
        top = joined.head(10)[["cve_id", "base_score", "base_severity", "epss", "percentile"]]
        print(f"\nTop {len(top)} by EPSS:\n{top.to_string(index=False)}")

    return joined


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


def _positive_int(value: str) -> int:
    """argparse type for options where zero or a negative number makes no sense."""
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return number


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Read the command-line options. The defaults reproduce a normal daily run."""
    parser = argparse.ArgumentParser(
        description="Join recent NVD CVEs with EPSS scores into one CSV ranked by EPSS.",
        epilog=NVD_NOTICE,
    )
    parser.add_argument(
        "--days",
        type=_positive_int,
        default=DEFAULT_WINDOW_DAYS,
        help="length of the CVE publication window in days; long windows are split "
        "automatically (default: %(default)s)",
    )
    parser.add_argument(
        "--as-of",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        metavar="YYYY-MM-DD",
        help="date to treat as today, to re-create a past run (default: today)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        metavar="DIR",
        help="folder for the CSV (default: current folder)",
    )
    parser.add_argument(
        "--epss-lookback",
        type=_positive_int,
        default=DEFAULT_EPSS_LOOKBACK_DAYS,
        metavar="DAYS",
        help="days to search backwards for an EPSS file (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns the process exit code."""
    args = _parse_args(argv)
    print(NVD_NOTICE)
    try:
        run_pipeline(
            as_of=args.as_of,
            days=args.days,
            # Taken from the environment, not a flag, to keep the key out of shell history.
            api_key=os.environ.get("NVD_API_KEY"),
            output_dir=args.output_dir,
            epss_lookback_days=args.epss_lookback,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        # Expected failures: network and HTTP errors (requests' exceptions are OSErrors),
        # a CSV still open in Excel, or unexpected data. Report them on one line and exit
        # non-zero so a scheduler notices. Anything else is a bug and keeps its traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
