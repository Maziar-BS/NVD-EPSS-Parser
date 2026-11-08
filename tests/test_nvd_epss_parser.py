"""Tests for nvd_epss_parser. None of them touch the network: HTTP calls are faked."""

import csv
import datetime as dt
import gzip
import json
from pathlib import Path
from unittest import mock

import pandas as pd
import pytest
import requests

import nvd_epss_parser as nep

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSVS = ["nvd_epss_joined_2026-07-29.csv", "nvd_epss_joined_2026-07-30.csv"]

START = dt.datetime(2026, 7, 23)
END = dt.datetime(2026, 7, 30)


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def sleep(monkeypatch):
    """Replace time.sleep so tests run instantly and can check the waits requested."""
    fake = mock.Mock()
    monkeypatch.setattr(nep.time, "sleep", fake)
    return fake


@pytest.fixture(autouse=True)
def http_get(monkeypatch):
    """Replace requests.get. A test sets .side_effect to script the server's replies."""
    fake = mock.Mock(side_effect=AssertionError("unexpected network call"))
    monkeypatch.setattr(nep.requests, "get", fake)
    return fake


def response(status=200, *, body=None, content=b"", headers=None):
    """Build a real requests.Response, so .ok, .json() and .raise_for_status() are real."""
    resp = requests.Response()
    resp.status_code = status
    resp._content = json.dumps(body).encode() if body is not None else content
    resp.headers.update(headers or {})
    return resp


def nvd_page(ids, total=None):
    """One page of an NVD response containing the given CVE IDs."""
    return response(
        body={
            "totalResults": len(ids) if total is None else total,
            "vulnerabilities": [{"cve": {"id": cve_id}} for cve_id in ids],
        }
    )


def epss_file(rows=("CVE-2026-0001,0.5,0.9",), header="cve,epss,percentile"):
    """A gzipped EPSS response laid out like the real files, comment line included."""
    text = "\n".join(["#model_version:v2026.06.15,score_date:2026-07-29T12:00:00Z", header, *rows])
    return response(content=gzip.compress(text.encode()))


def metric(version, score, severity="HIGH"):
    """One CVSS v3.x metrics entry, with baseSeverity inside cvssData as NVD returns it."""
    return {
        "cvssData": {
            "version": version,
            "baseScore": score,
            "baseSeverity": severity,
            "vectorString": f"CVSS:{version}/test",
        }
    }


def nvd_table(*ids):
    """A minimal NVD table with the given CVE IDs."""
    return nep.parse_nvd_cves([{"id": cve_id} for cve_id in ids])


def sent_params(http_get):
    """The query parameters of every request made so far."""
    return [call.kwargs["params"] for call in http_get.call_args_list]


# ---------------------------------------------------------------------------
# Retrying requests: _get_with_retry()
# ---------------------------------------------------------------------------


def test_retry_recovers_from_server_error_with_growing_waits(http_get, sleep):
    http_get.side_effect = [response(503), response(503), response(200)]

    assert nep._get_with_retry("https://test.invalid").status_code == 200
    assert [call.args[0] for call in sleep.call_args_list] == [5.0, 10.0]


# Listed by hand rather than read from nep.RETRYABLE_STATUS_CODES, so that dropping a code
# there (403 is NVD's rate-limit response) makes this test fail.
@pytest.mark.parametrize("status", [403, 429, 500, 502, 503, 504])
def test_retry_gives_up_and_returns_the_last_response(http_get, status):
    http_get.side_effect = lambda *args, **kwargs: response(status)

    assert nep._get_with_retry("https://test.invalid").status_code == status
    assert http_get.call_count == nep.MAX_RETRIES + 1


def test_retry_does_not_repeat_a_definite_answer(http_get, sleep):
    http_get.side_effect = [response(404)]

    assert nep._get_with_retry("https://test.invalid").status_code == 404
    sleep.assert_not_called()


@pytest.mark.parametrize(
    "error", [requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError]
)
def test_retry_recovers_from_connection_problems(http_get, error):
    http_get.side_effect = [error("boom"), response(200)]

    assert nep._get_with_retry("https://test.invalid").status_code == 200


def test_retry_raises_when_the_connection_never_recovers(http_get):
    http_get.side_effect = requests.Timeout("too slow")

    with pytest.raises(requests.Timeout):
        nep._get_with_retry("https://test.invalid")
    assert http_get.call_count == nep.MAX_RETRIES + 1


# ---------------------------------------------------------------------------
# Stage 1: fetch_nvd_cves()
# ---------------------------------------------------------------------------


def test_fetch_follows_pagination_until_all_results_arrive(http_get):
    http_get.side_effect = [nvd_page(["CVE-1", "CVE-2"], total=3), nvd_page(["CVE-3"], total=3)]

    cves = nep.fetch_nvd_cves(START, END, results_per_page=2)

    assert [cve["id"] for cve in cves] == ["CVE-1", "CVE-2", "CVE-3"]
    assert [p["startIndex"] for p in sent_params(http_get)] == [0, 2]


def test_fetch_sends_dates_in_the_format_nvd_expects(http_get):
    http_get.side_effect = [nvd_page(["CVE-1"])]

    nep.fetch_nvd_cves(START, END)

    params = sent_params(http_get)[0]
    assert params["pubStartDate"] == "2026-07-23T00:00:00.000"
    assert params["pubEndDate"] == "2026-07-30T00:00:00.000"
    assert params["resultsPerPage"] == 2000


def test_fetch_without_key_sends_no_header_and_sleeps_six_seconds(http_get, sleep):
    http_get.side_effect = [nvd_page(["CVE-1"], total=2), nvd_page(["CVE-2"], total=2)]

    nep.fetch_nvd_cves(START, END)

    assert http_get.call_args.kwargs["headers"] == {}
    sleep.assert_called_once_with(6.0)


def test_fetch_with_key_sends_header_and_sleeps_less(http_get, sleep):
    http_get.side_effect = [nvd_page(["CVE-1"], total=2), nvd_page(["CVE-2"], total=2)]

    nep.fetch_nvd_cves(START, END, api_key="secret")

    assert http_get.call_args.kwargs["headers"] == {"apiKey": "secret"}
    sleep.assert_called_once_with(0.6)


def test_fetch_does_not_sleep_after_the_last_page(http_get, sleep):
    http_get.side_effect = [nvd_page(["CVE-1"])]

    nep.fetch_nvd_cves(START, END)

    sleep.assert_not_called()


def test_fetch_short_page_does_not_skip_records(http_get):
    # The server sends one record although two were requested. The next request has
    # to resume at index 1. Stepping by the page size would lose CVE-2.
    http_get.side_effect = [nvd_page(["CVE-1"], total=3), nvd_page(["CVE-2", "CVE-3"], total=3)]

    cves = nep.fetch_nvd_cves(START, END, results_per_page=2)

    assert [p["startIndex"] for p in sent_params(http_get)] == [0, 1]
    assert [cve["id"] for cve in cves] == ["CVE-1", "CVE-2", "CVE-3"]


def test_fetch_empty_page_mid_results_raises_instead_of_looping_forever(http_get):
    http_get.side_effect = [nvd_page(["CVE-1"], total=2), nvd_page([], total=2)]

    with pytest.raises(RuntimeError, match="incomplete"):
        nep.fetch_nvd_cves(START, END)


def test_fetch_window_with_no_cves_returns_empty_list(http_get):
    http_get.side_effect = [nvd_page([])]

    assert nep.fetch_nvd_cves(START, END) == []
    assert http_get.call_count == 1


def test_fetch_splits_long_ranges_and_removes_boundary_duplicates(http_get, sleep):
    # A 200-day range takes three requests. CVE-2 sits on the boundary between the
    # first two windows, and NVD includes both ends of a range, so it arrives twice.
    http_get.side_effect = [nvd_page(["CVE-1", "CVE-2"]), nvd_page(["CVE-2", "CVE-3"]), nvd_page([])]

    cves = nep.fetch_nvd_cves(dt.datetime(2026, 1, 1), dt.datetime(2026, 7, 20))

    assert [cve["id"] for cve in cves] == ["CVE-1", "CVE-2", "CVE-3"]
    assert sleep.call_count == 2  # One wait between each of the three windows.

    parse = lambda text: dt.datetime.strptime(text, nep.NVD_DATE_FORMAT)
    windows = [(parse(p["pubStartDate"]), parse(p["pubEndDate"])) for p in sent_params(http_get)]
    assert all(end - start <= dt.timedelta(days=120) for start, end in windows)
    assert windows[0][0] == dt.datetime(2026, 1, 1)
    assert windows[-1][1] == dt.datetime(2026, 7, 20)
    assert all(a[1] == b[0] for a, b in zip(windows, windows[1:]))  # No gaps.


@pytest.mark.parametrize("start, end", [(END, START), (START, START)])
def test_fetch_rejects_an_empty_or_reversed_range(start, end):
    with pytest.raises(ValueError, match="Empty date range"):
        nep.fetch_nvd_cves(start, end)


def test_fetch_error_includes_the_reason_nvd_gives(http_get):
    http_get.side_effect = [response(404, headers={"message": "Invalid apiKey."})]

    with pytest.raises(requests.HTTPError, match="HTTP 404: Invalid apiKey."):
        nep.fetch_nvd_cves(START, END)


# ---------------------------------------------------------------------------
# Stage 2: _extract_cvss() and parse_nvd_cves()
# ---------------------------------------------------------------------------


def test_cvss_prefers_v31_over_older_versions():
    metrics = {
        "cvssMetricV2": [metric("2.0", 5.0)],
        "cvssMetricV30": [metric("3.0", 7.0)],
        "cvssMetricV31": [metric("3.1", 9.8, "CRITICAL")],
    }

    assert nep._extract_cvss(metrics) == {
        "cvss_version": "3.1",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
        "vector_string": "CVSS:3.1/test",
    }


def test_cvss_falls_back_to_v30_then_v2():
    v30 = {"cvssMetricV2": [metric("2.0", 5.0)], "cvssMetricV30": [metric("3.0", 7.0)]}
    assert nep._extract_cvss(v30)["cvss_version"] == "3.0"

    v2 = {"cvssMetricV2": [metric("2.0", 5.0)]}
    assert nep._extract_cvss(v2)["cvss_version"] == "2.0"


def test_cvss_treats_an_empty_list_as_missing():
    metrics = {"cvssMetricV31": [], "cvssMetricV30": [metric("3.0", 7.0)]}

    assert nep._extract_cvss(metrics)["cvss_version"] == "3.0"


def test_cvss_reads_v2_severity_from_beside_cvssdata():
    # Unlike v3.x, a v2 entry keeps baseSeverity outside the cvssData object.
    entry = {"baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 5.0}}

    assert nep._extract_cvss({"cvssMetricV2": [entry]})["base_severity"] == "MEDIUM"


def test_cvss_uses_the_first_entry_of_a_version():
    metrics = {"cvssMetricV31": [metric("3.1", 9.8), metric("3.1", 1.0)]}

    assert nep._extract_cvss(metrics)["base_score"] == 9.8


@pytest.mark.parametrize(
    "metrics",
    [
        {},
        {"cvssMetricV40": [metric("4.0", 9.3)]},  # v4.0 is outside the preference order.
        {"ssvcV203": [{"ssvcData": {}}]},  # Real records carry non-CVSS metrics too.
    ],
)
def test_cvss_is_all_none_when_no_supported_version_exists(metrics):
    assert set(nep._extract_cvss(metrics).values()) == {None}


def test_parse_flattens_a_record_like_the_ones_nvd_returns():
    raw = {
        "id": "CVE-2026-6516",
        "published": "2026-07-23T18:17:02.570",
        "lastModified": "2026-07-24T05:16:50.033",
        "descriptions": [
            {"lang": "es", "value": "Descripcion"},
            {"lang": "en", "value": "Description"},
        ],
        "metrics": {"cvssMetricV31": [metric("3.1", 10.0, "CRITICAL")]},
    }

    table = nep.parse_nvd_cves([raw])

    assert list(table.columns) == nep.NVD_COLUMNS
    row = table.iloc[0]
    assert row["cve_id"] == "CVE-2026-6516"
    assert row["published"] == "2026-07-23T18:17:02.570"
    assert row["last_modified"] == "2026-07-24T05:16:50.033"
    assert row["description"] == "Description"
    assert row["base_score"] == 10.0


def test_parse_uses_empty_description_when_there_is_no_english_text():
    raw = {"id": "CVE-1", "descriptions": [{"lang": "es", "value": "Descripcion"}]}

    assert nep.parse_nvd_cves([raw]).iloc[0]["description"] == ""


def test_parse_no_cves_still_gives_all_the_columns():
    table = nep.parse_nvd_cves([])

    assert table.empty
    assert list(table.columns) == nep.NVD_COLUMNS


# ---------------------------------------------------------------------------
# Stage 3: fetch_epss_scores()
# ---------------------------------------------------------------------------


def test_epss_reads_the_file_and_stamps_the_score_date(http_get):
    http_get.side_effect = [epss_file(["CVE-1,0.25,0.75"])]

    df = nep.fetch_epss_scores(dt.date(2026, 7, 29))

    assert list(df.columns) == ["cve", "epss", "percentile"]  # Comment line was skipped.
    assert df.iloc[0].to_dict() == {"cve": "CVE-1", "epss": 0.25, "percentile": 0.75}
    assert df.attrs["score_date"] == "2026-07-29"
    assert http_get.call_args.args[0] == f"{nep.EPSS_RAW_BASE}/2026/epss_scores-2026-07-29.csv.gz"


def test_epss_steps_back_a_day_at_a_time_over_missing_files(http_get):
    http_get.side_effect = [response(404), response(404), epss_file()]

    df = nep.fetch_epss_scores(dt.date(2026, 7, 29))

    assert df.attrs["score_date"] == "2026-07-27"
    assert http_get.call_count == 3


def test_epss_lookback_crosses_into_the_previous_years_folder(http_get):
    http_get.side_effect = [response(404), epss_file()]

    nep.fetch_epss_scores(dt.date(2026, 1, 1))

    assert http_get.call_args.args[0].endswith("/2025/epss_scores-2025-12-31.csv.gz")


def test_epss_raises_when_every_day_is_missing(http_get):
    http_get.side_effect = lambda *args, **kwargs: response(404)

    with pytest.raises(FileNotFoundError, match="3 days up to 2026-07-29"):
        nep.fetch_epss_scores(dt.date(2026, 7, 29), max_lookback_days=3)
    assert http_get.call_count == 3


def test_epss_outage_raises_instead_of_using_stale_scores(http_get):
    # The day's file exists but the server is failing. Stepping back here would quietly
    # return older scores, so only a real 404 is allowed to do that.
    http_get.side_effect = lambda *args, **kwargs: response(500)

    with pytest.raises(requests.HTTPError):
        nep.fetch_epss_scores(dt.date(2026, 7, 29))
    assert all("2026-07-29" in call.args[0] for call in http_get.call_args_list)


def test_epss_rejects_a_file_with_unexpected_columns(http_get):
    http_get.side_effect = [epss_file(["CVE-1,0.25"], header="cve,score")]

    with pytest.raises(ValueError, match="missing columns"):
        nep.fetch_epss_scores(dt.date(2026, 7, 29))


# ---------------------------------------------------------------------------
# Stage 4: join_and_rank()
# ---------------------------------------------------------------------------


def epss_table(*rows):
    return pd.DataFrame(rows, columns=["cve", "epss", "percentile"])


def test_join_keeps_unscored_cves_and_ranks_them_last():
    joined = nep.join_and_rank(
        nvd_table("CVE-LOW", "CVE-NONE", "CVE-HIGH"),
        epss_table(("CVE-HIGH", 0.9, 0.99), ("CVE-LOW", 0.1, 0.5), ("CVE-OTHER", 0.5, 0.8)),
    )

    # CVE-OTHER is only in EPSS, so it is not part of this table.
    assert joined["cve_id"].tolist() == ["CVE-HIGH", "CVE-LOW", "CVE-NONE"]
    assert pd.isna(joined.loc[2, "epss"])
    assert pd.isna(joined.loc[2, "percentile"])


def test_join_breaks_epss_ties_by_percentile_then_cve_id():
    joined = nep.join_and_rank(
        nvd_table("CVE-D", "CVE-C", "CVE-B", "CVE-A"),
        epss_table(("CVE-A", 0.5, 0.7), ("CVE-B", 0.5, 0.7), ("CVE-C", 0.5, 0.9), ("CVE-D", 0.6, 0.1)),
    )

    assert joined["cve_id"].tolist() == ["CVE-D", "CVE-C", "CVE-A", "CVE-B"]


def test_join_order_does_not_depend_on_input_order():
    epss = epss_table(("CVE-A", 0.5, 0.7), ("CVE-B", 0.5, 0.7))
    forward = nep.join_and_rank(nvd_table("CVE-A", "CVE-B", "CVE-C", "CVE-D"), epss)
    backward = nep.join_and_rank(nvd_table("CVE-D", "CVE-C", "CVE-B", "CVE-A"), epss)

    pd.testing.assert_frame_equal(forward, backward)


def test_join_output_has_exactly_the_contract_columns():
    epss = epss_table(("CVE-A", 0.5, 0.7)).assign(extra_column=1)

    joined = nep.join_and_rank(nvd_table("CVE-A"), epss)

    assert list(joined.columns) == nep.OUTPUT_COLUMNS


def test_join_refuses_to_duplicate_rows_when_epss_lists_a_cve_twice():
    with pytest.raises(pd.errors.MergeError):
        nep.join_and_rank(
            nvd_table("CVE-A"), epss_table(("CVE-A", 0.5, 0.7), ("CVE-A", 0.6, 0.8))
        )


# ---------------------------------------------------------------------------
# Stage 5: export_csv()
# ---------------------------------------------------------------------------


def test_export_names_the_file_by_date_and_creates_the_folder(tmp_path):
    joined = nep.join_and_rank(nvd_table("CVE-A"), epss_table())

    path = nep.export_csv(joined, dt.date(2026, 7, 30), tmp_path / "new" / "folder")

    assert path == tmp_path / "new" / "folder" / "nvd_epss_joined_2026-07-30.csv"
    assert path.exists()


def test_export_writes_missing_values_as_blank_cells_and_no_index(tmp_path):
    joined = nep.join_and_rank(nvd_table("CVE-A"), epss_table())

    path = nep.export_csv(joined, dt.date(2026, 7, 30), tmp_path)

    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == nep.OUTPUT_COLUMNS
    assert rows[1][0] == "CVE-A"
    assert rows[1][4:] == [""] * 6  # Blank CVSS and EPSS cells.


# ---------------------------------------------------------------------------
# The sample outputs in this repository, used as golden files
# ---------------------------------------------------------------------------


def read_sample(name):
    with (REPO_ROOT / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def raw_cve_from_sample_row(row):
    """Rebuild the NVD JSON record that a sample row was produced from."""
    metrics = {}
    if row["cvss_version"]:
        key = {"3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "2.0": "cvssMetricV2"}
        metrics[key[row["cvss_version"]]] = [
            {
                "cvssData": {
                    "version": row["cvss_version"],
                    "baseScore": float(row["base_score"]),
                    "baseSeverity": row["base_severity"],
                    "vectorString": row["vector_string"],
                }
            }
        ]
    return {
        "id": row["cve_id"],
        "published": row["published"],
        "lastModified": row["last_modified"],
        "descriptions": [{"lang": "en", "value": row["description"]}],
        "metrics": metrics,
    }


def physical_lines(path):
    """A file's sorted lines as bytes, with row order and CRLF/LF differences removed."""
    return sorted(path.read_bytes().replace(b"\r\n", b"\n").split(b"\n"))


@pytest.mark.parametrize("sample", SAMPLE_CSVS)
def test_pipeline_reproduces_every_line_of_the_sample_output(sample, tmp_path):
    rows = read_sample(sample)
    raw_cves = [raw_cve_from_sample_row(row) for row in rows]
    epss = pd.DataFrame(
        [(r["cve_id"], float(r["epss"]), float(r["percentile"])) for r in rows if r["epss"]],
        columns=["cve", "epss", "percentile"],
    )

    joined = nep.join_and_rank(nep.parse_nvd_cves(raw_cves), epss)
    path = nep.export_csv(joined, dt.date.fromisoformat(sample[16:26]), tmp_path)

    assert path.name == sample
    # Identical bytes per line prove the quoting, number formatting ("10.0", "0.0754"),
    # blank cells, multi-line descriptions and encoding all match the samples.
    assert physical_lines(path) == physical_lines(REPO_ROOT / sample)


@pytest.mark.parametrize("sample", SAMPLE_CSVS)
def test_samples_follow_the_documented_output_contract(sample):
    rows = read_sample(sample)
    assert list(rows[0]) == nep.OUTPUT_COLUMNS

    ids = [row["cve_id"] for row in rows]
    assert len(ids) == len(set(ids))

    scored = [float(row["epss"]) for row in rows if row["epss"]]
    assert scored == sorted(scored, reverse=True)
    assert not any(row["epss"] for row in rows[len(scored):])  # Unscored rows are last.


# ---------------------------------------------------------------------------
# The whole pipeline and the command line
# ---------------------------------------------------------------------------


def fake_server(cves, epss_rows=("CVE-2026-0001,0.5,0.9",)):
    """A stand-in for requests.get that answers like NVD and the EPSS mirror."""

    def get(url, params=None, headers=None, timeout=None):
        if url == nep.NVD_API_BASE:
            return response(
                body={"totalResults": len(cves), "vulnerabilities": [{"cve": c} for c in cves]}
            )
        return epss_file(epss_rows)

    return get


CVE = {
    "id": "CVE-2026-0001",
    "published": "2026-07-29T10:00:00.000",
    "lastModified": "2026-07-29T11:00:00.000",
    "descriptions": [{"lang": "en", "value": "Line one\nline two, with a comma"}],
    "metrics": {"cvssMetricV31": [metric("3.1", 9.8, "CRITICAL")]},
}


def test_pipeline_runs_every_stage_for_the_requested_date(http_get, tmp_path, capsys):
    http_get.side_effect = fake_server([CVE])

    joined = nep.run_pipeline(dt.date(2026, 7, 30), output_dir=tmp_path)

    # The window is the 7 days before as_of, and the EPSS date is the day before as_of.
    params = sent_params(http_get)[0]
    assert params["pubStartDate"] == "2026-07-23T00:00:00.000"
    assert params["pubEndDate"] == "2026-07-30T00:00:00.000"
    assert http_get.call_args_list[1].args[0].endswith("epss_scores-2026-07-29.csv.gz")

    assert joined.iloc[0]["epss"] == 0.5
    output = pd.read_csv(tmp_path / "nvd_epss_joined_2026-07-30.csv")
    assert output.iloc[0]["description"] == "Line one\nline two, with a comma"

    printed = capsys.readouterr().out
    assert "NVD CVEs fetched: 1" in printed
    assert "EPSS score date used: 2026-07-29 (1 rows)" in printed
    assert "Matched 1/1 NVD CVEs to an EPSS score (100.0%)" in printed
    assert "Wrote 1 rows to" in printed
    assert "CVE-2026-0001" in printed


def test_pipeline_handles_a_window_with_no_cves(http_get, tmp_path, capsys):
    http_get.side_effect = fake_server([])

    joined = nep.run_pipeline(dt.date(2026, 7, 30), output_dir=tmp_path)

    assert joined.empty
    assert "Matched 0/0 NVD CVEs to an EPSS score (n/a)" in capsys.readouterr().out
    written = (tmp_path / "nvd_epss_joined_2026-07-30.csv").read_text(encoding="utf-8")
    assert written.strip() == ",".join(nep.OUTPUT_COLUMNS)


def test_cli_success_uses_the_environment_key_and_prints_the_nvd_notice(
    http_get, tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    http_get.side_effect = fake_server([CVE])

    code = nep.main(["--as-of", "2026-07-30", "--days", "3", "--output-dir", str(tmp_path)])

    assert code == 0
    assert http_get.call_args_list[0].kwargs["headers"] == {"apiKey": "secret"}
    assert sent_params(http_get)[0]["pubStartDate"] == "2026-07-27T00:00:00.000"
    assert (tmp_path / "nvd_epss_joined_2026-07-30.csv").exists()
    captured = capsys.readouterr()
    assert nep.NVD_NOTICE in captured.out
    assert "secret" not in captured.out + captured.err


def test_cli_failure_prints_one_line_and_exits_nonzero(http_get, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    http_get.side_effect = [response(404, headers={"message": "Invalid apiKey."})]

    code = nep.main(["--as-of", "2026-07-30", "--output-dir", str(tmp_path)])

    assert code == 1
    assert capsys.readouterr().err == "error: NVD API returned HTTP 404: Invalid apiKey.\n"


@pytest.mark.parametrize(
    "arguments", [["--days", "0"], ["--days", "-3"], ["--as-of", "not-a-date"], ["--epss-lookback", "0"]]
)
def test_cli_rejects_invalid_options(arguments, capsys):
    with pytest.raises(SystemExit) as exit_info:
        nep.main(arguments)

    assert exit_info.value.code == 2
    assert "usage:" in capsys.readouterr().err
