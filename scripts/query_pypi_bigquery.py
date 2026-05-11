# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptography",
#     "google-auth",
#     "httpx",
#     "packaging",
#     "rich",
# ]
# ///
"""Sync PyPI distribution metadata into SQLite, enrich it with PyPI
provenance, and optionally submit entries to bt-log.

The script is intentionally split into resumable subcommands:

    bigquery    ingest raw package/file rows from BigQuery
    provenance  enrich unchecked rows with provenance status
    submit      submit unlogged rows to bt-log

Each command commits incremental progress so an interrupted run can be safely
started again.
"""

import argparse
import base64
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import urljoin, urlparse

import google.auth
import google.auth.transport.requests
import httpx
from cryptography import x509
from packaging.utils import canonicalize_name
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

NUM_WORKERS = 10
WORKER_DELAY = 0.25
BQ_BASE = "https://bigquery.googleapis.com/bigquery/v2/projects"
CONSOLE = Console(stderr=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(console=CONSOLE, show_time=False, show_path=False, markup=False)],
)
log = logging.getLogger(__name__)


@dataclass
class Publisher:
    kind: str
    subject: str


@dataclass
class LogEntry:
    filename: str
    sha256_digest: str
    upload_time: str
    publisher: Publisher | None = None


@dataclass
class RawEntry:
    package_name: str
    filename: str
    sha256_digest: str
    upload_time: str


@dataclass
class ProvenanceTarget:
    package_name: str
    filename: str
    sha256_digest: str


def add_common_args(p: argparse.ArgumentParser):
    p.add_argument(
        "--db",
        default=os.environ.get("PYPI_INGEST_DB", "pypi_entries.db"),
        help="path to SQLite database (default: $PYPI_INGEST_DB or pypi_entries.db)",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("PYPI_INGEST_LOG_LEVEL", "INFO"),
        help="Python logging level (default: INFO)",
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Sync PyPI metadata from BigQuery to SQLite, enrich provenance, and submit to bt-log",
    )
    sub = p.add_subparsers(dest="command", required=True)

    bq = sub.add_parser("bigquery", help="populate SQLite with raw BigQuery rows")
    add_common_args(bq)
    bq.add_argument("--since", help="initial lower bound when no cursor exists; Unix seconds or ISO/RFC3339")
    bq.add_argument("--batch-size", type=int, default=50_000, help="rows per committed BigQuery batch")
    bq.add_argument("--max-rows", type=int, help="maximum rows to ingest in this run")
    bq.add_argument("--no-count", action="store_true", help="skip initial COUNT(*) used for progress ETA")

    prov = sub.add_parser("provenance", help="populate provenance for unchecked SQLite entries")
    add_common_args(prov)
    prov.add_argument("--batch-size", type=int, default=5_000, help="unchecked DB rows to load per loop")
    prov.add_argument("--max-entries", type=int, help="maximum entries to process in this run")
    prov.add_argument("--retry-failed", action="store_true", help="also retry rows with provenance_status='failed'")
    prov.add_argument("--no-count", action="store_true", help="skip initial COUNT(*) used for progress ETA")

    submit = sub.add_parser("submit", help="submit unlogged SQLite entries to bt-log")
    add_common_args(submit)
    submit.add_argument(
        "--log-url",
        default=os.environ.get("BT_LOG_URL", "http://localhost:8080"),
        help="base URL of bt-log (default: $BT_LOG_URL or http://localhost:8080)",
    )
    submit.add_argument("--timeout", type=float, default=float(os.environ.get("PYPI_INGEST_TIMEOUT", "30")))
    submit.add_argument("--retries", type=int, default=int(os.environ.get("PYPI_INGEST_RETRIES", "3")))
    submit.add_argument(
        "--retry-backoff",
        type=float,
        default=float(os.environ.get("PYPI_INGEST_RETRY_BACKOFF", "1")),
    )
    submit.add_argument("--max-submit", type=int, help="maximum unlogged entries to submit in this run")
    return p.parse_args()


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            package_name          TEXT NOT NULL,
            filename              TEXT NOT NULL,
            sha256_digest         TEXT NOT NULL,
            publisher_kind        TEXT,
            publisher_subject     TEXT,
            upload_time           TEXT NOT NULL,
            provenance_status     TEXT NOT NULL DEFAULT 'unchecked',
            provenance_checked_at TEXT,
            provenance_error      TEXT,
            UNIQUE(filename, sha256_digest)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logged_entries (
            filename      TEXT NOT NULL,
            sha256_digest TEXT NOT NULL,
            logged_at     TEXT NOT NULL,
            log_index     TEXT,
            UNIQUE(filename, sha256_digest)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cursor (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    _migrate_entries(conn)
    conn.commit()
    return conn


def _migrate_entries(conn: sqlite3.Connection):
    cols = {row[1] for row in conn.execute("PRAGMA table_info(entries)")}
    migrations = {
        "package_name": "ALTER TABLE entries ADD COLUMN package_name TEXT",
        "provenance_status": "ALTER TABLE entries ADD COLUMN provenance_status TEXT NOT NULL DEFAULT 'unchecked'",
        "provenance_checked_at": "ALTER TABLE entries ADD COLUMN provenance_checked_at TEXT",
        "provenance_error": "ALTER TABLE entries ADD COLUMN provenance_error TEXT",
    }
    for col, sql in migrations.items():
        if col not in cols:
            conn.execute(sql)


def get_cursor_value(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM cursor WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_cursor_values(conn: sqlite3.Connection, values: dict[str, str]):
    for key, value in values.items():
        conn.execute(
            """INSERT INTO cursor (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )


def get_bq_auth() -> tuple[str, str]:
    """Return (access_token, project_id) from ADC."""
    scopes = [
        "https://www.googleapis.com/auth/bigquery.readonly",
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ]
    creds, project = google.auth.default(scopes=scopes)
    if getattr(creds, "requires_scopes", False):
        creds = creds.with_scopes(scopes)
    creds.refresh(google.auth.transport.requests.Request())
    if not project:
        project = _discover_project(creds.token)
    return creds.token, project


def _discover_project(token: str) -> str:
    resp = httpx.get(
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        params={"pageSize": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    resp.raise_for_status()
    projects = resp.json().get("projects", [])
    if not projects:
        raise RuntimeError("No GCP projects found. Set a default project with: gcloud config set project PROJECT_ID")
    return projects[0]["projectId"]


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=CONSOLE,
    )


def _upload_time_to_micros(upload_time: str) -> int:
    return int(
        (Decimal(str(upload_time)) * Decimal(1_000_000)).to_integral_value(
            rounding=ROUND_HALF_UP
        )
    )


def _normalize_upload_time(upload_time: str) -> str:
    micros = _upload_time_to_micros(upload_time)
    return f"{micros // 1_000_000}.{micros % 1_000_000:06d}"


def _format_upload_time(upload_time: str | None) -> str:
    if not upload_time:
        return ""
    try:
        dt = datetime.fromtimestamp(float(upload_time), tz=timezone.utc)
        return f"{_normalize_upload_time(upload_time)} ({dt.isoformat()})"
    except Exception:
        return upload_time


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _bq_request(
    method: str,
    url: str,
    headers: dict,
    json_body: dict | None = None,
    params: dict | None = None,
    max_retries: int = 3,
) -> dict:
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=120) as client:
                resp = client.request(method, url, headers=headers, json=json_body, params=params)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            if attempt == max_retries - 1:
                raise
            wait = 2 ** (attempt + 1)
            CONSOLE.print(f"BigQuery request failed: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _bigquery_where(
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
) -> str:
    where = "WHERE sha256_digest IS NOT NULL"
    if last_upload_time:
        micros = _upload_time_to_micros(last_upload_time)
        ts = f"TIMESTAMP_MICROS({micros})"
        filename = _sql_string(last_filename or "")
        digest = _sql_string(last_sha256_digest or "")
        where += f"""
              AND (
                upload_time > {ts}
                OR (upload_time = {ts} AND filename > {filename})
                OR (upload_time = {ts} AND filename = {filename} AND sha256_digest > {digest})
              )"""
    return where


def query_bigquery_count(
    token: str,
    project: str,
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
) -> int:
    where = _bigquery_where(last_upload_time, last_filename, last_sha256_digest)
    query = f"""
            SELECT COUNT(1) AS row_count
            FROM `bigquery-public-data.pypi.distribution_metadata`
            {where}
        """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data = _bq_request(
        "POST",
        f"{BQ_BASE}/{project}/queries",
        headers=headers,
        json_body={"query": query, "useLegacySql": False, "maxResults": 1},
    )
    job_id = data["jobReference"]["jobId"]
    while not data.get("jobComplete"):
        time.sleep(2)
        data = _bq_request(
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            headers=headers,
            params={"maxResults": 1},
        )
    rows = data.get("rows", [])
    return int(rows[0]["f"][0]["v"]) if rows else 0


def query_bigquery_batch(
    token: str,
    project: str,
    last_upload_time: str | None,
    last_filename: str | None,
    last_sha256_digest: str | None,
    batch_size: int,
) -> list[RawEntry]:
    where = _bigquery_where(last_upload_time, last_filename, last_sha256_digest)
    query = f"""
            SELECT name, filename, sha256_digest, upload_time
            FROM `bigquery-public-data.pypi.distribution_metadata`
            {where}
            ORDER BY upload_time ASC, filename ASC, sha256_digest ASC
            LIMIT {batch_size}
        """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data = _bq_request(
        "POST",
        f"{BQ_BASE}/{project}/queries",
        headers=headers,
        json_body={"query": query, "useLegacySql": False, "maxResults": batch_size},
    )
    job_id = data["jobReference"]["jobId"]
    while not data.get("jobComplete"):
        time.sleep(2)
        data = _bq_request("GET", f"{BQ_BASE}/{project}/queries/{job_id}", headers=headers, params={"maxResults": batch_size})

    fields = [f["name"] for f in data["schema"]["fields"]]
    rows: list[RawEntry] = []
    while True:
        for row in data.get("rows", []):
            values = [cell["v"] for cell in row["f"]]
            d = dict(zip(fields, values))
            rows.append(
                RawEntry(
                    d["name"],
                    d["filename"],
                    d["sha256_digest"],
                    _normalize_upload_time(d["upload_time"]),
                )
            )
        page_token = data.get("pageToken")
        if not page_token:
            break
        data = _bq_request(
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            headers=headers,
            params={"maxResults": batch_size, "pageToken": page_token},
        )
    return rows


def insert_raw_entries_and_cursor(conn: sqlite3.Connection, rows: list[RawEntry]) -> int:
    inserted = 0
    with conn:
        for row in rows:
            conn.execute(
                """INSERT OR IGNORE INTO entries
                   (package_name, filename, sha256_digest, upload_time, provenance_status)
                   VALUES (?, ?, ?, ?, 'unchecked')""",
                (row.package_name, row.filename, row.sha256_digest, row.upload_time),
            )
            if conn.execute("SELECT changes()").fetchone()[0] > 0:
                inserted += 1
        last = rows[-1]
        set_cursor_values(
            conn,
            {
                "bigquery_last_upload_time": last.upload_time,
                "bigquery_last_filename": last.filename,
                "bigquery_last_sha256_digest": last.sha256_digest,
            },
        )
    return inserted


def run_bigquery(args) -> None:
    conn = init_db(args.db)
    last_upload_time = get_cursor_value(conn, "bigquery_last_upload_time")
    last_filename = get_cursor_value(conn, "bigquery_last_filename")
    last_digest = get_cursor_value(conn, "bigquery_last_sha256_digest")
    if not last_upload_time:
        last_upload_time = _since_to_upload_time(args.since)
        if last_upload_time:
            last_filename = ""
            last_digest = ""
    if last_upload_time:
        CONSOLE.print(
            f"Resuming BigQuery from {_format_upload_time(last_upload_time)} / "
            f"{last_filename or ''} / {last_digest or ''}"
        )
    else:
        CONSOLE.print("First BigQuery run: fetching all entries")

    token, project = get_bq_auth()
    CONSOLE.print(f"Using project: {project}")
    progress_total = None
    if not args.no_count:
        CONSOLE.print("Counting remaining BigQuery rows for progress ETA...")
        progress_total = query_bigquery_count(token, project, last_upload_time, last_filename, last_digest)
        if args.max_rows is not None:
            progress_total = min(progress_total, args.max_rows)
        CONSOLE.print(f"Rows to ingest this run: {progress_total}")

    total_fetched = total_inserted = 0
    start = time.monotonic()
    with make_progress() as progress:
        task = progress.add_task("Ingesting BigQuery rows", total=progress_total)
        while True:
            remaining = None if args.max_rows is None else args.max_rows - total_fetched
            if remaining is not None and remaining <= 0:
                break
            batch_size = min(args.batch_size, remaining) if remaining is not None else args.batch_size
            rows = query_bigquery_batch(token, project, last_upload_time, last_filename, last_digest, batch_size)
            if not rows:
                break
            inserted = insert_raw_entries_and_cursor(conn, rows)
            total_fetched += len(rows)
            total_inserted += inserted
            last = rows[-1]
            last_upload_time, last_filename, last_digest = last.upload_time, last.filename, last.sha256_digest
            progress.update(task, advance=len(rows))
            log.debug(
                "Committed BigQuery batch: fetched=%d inserted=%d cursor=%s",
                len(rows),
                inserted,
                _format_upload_time(last_upload_time),
            )
            if len(rows) < batch_size:
                break
    conn.close()
    CONSOLE.print(f"Done: fetched={total_fetched}, inserted={total_inserted}, elapsed={time.monotonic() - start:.1f}s")


def publisher_from_cert(filename: str, cert_b64: str) -> Publisher | None:
    try:
        cert_bytes = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_bytes)
    except Exception:
        log.warning("Failed to parse certificate for %s", filename)
        return None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        return None
    if not uris:
        return None
    subject = uris[0]
    return Publisher(kind=_publisher_kind(subject), subject=subject)


def _publisher_kind(subject: str) -> str:
    try:
        parsed = urlparse(subject)
        host = parsed.hostname or ""
        if host.startswith("www."):
            host = host[4:]
        kind, _, _ = host.partition(".")
        return kind or "unknown"
    except Exception:
        return "unknown"


def _fetch_provenance_bundle(filename: str, prov_url: str, client: httpx.Client) -> Publisher | None:
    try:
        resp = client.get(prov_url)
        resp.raise_for_status()
        bundle = resp.json()
    except Exception:
        log.warning("Failed to fetch provenance for %s", filename)
        return None
    att_bundles = bundle.get("attestation_bundles", [])
    if not att_bundles:
        return None
    attestations = att_bundles[0].get("attestations", [])
    if not attestations:
        return None
    cert_b64 = attestations[0].get("verification_material", {}).get("certificate", "")
    if not cert_b64:
        return None
    return publisher_from_cert(filename, cert_b64)


def fetch_package_provenance(
    pkg_name: str,
    filenames: set[str],
    client: httpx.Client,
) -> tuple[bool, dict[str, Publisher | None], str | None]:
    """Return (ok, filename->publisher/None, error)."""
    url = f"https://pypi.org/simple/{canonicalize_name(pkg_name)}/"
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    try:
        resp = client.get(url, headers=headers)
    except httpx.HTTPError as e:
        return False, {}, str(e)
    if resp.status_code != 200:
        return False, {}, f"Simple API returned {resp.status_code}"
    try:
        data = resp.json()
    except Exception as e:
        return False, {}, f"failed to parse Simple API JSON: {e}"

    result: dict[str, Publisher | None] = {name: None for name in filenames}
    for f in data.get("files", []):
        fname = f.get("filename", "")
        if fname not in filenames:
            continue
        prov_url = f.get("provenance")
        result[fname] = _fetch_provenance_bundle(fname, prov_url, client) if prov_url else None
    return True, result, None


def _provenance_statuses(retry_failed: bool) -> str:
    return "'unchecked', 'failed'" if retry_failed else "'unchecked'"


def count_provenance_targets(conn: sqlite3.Connection, retry_failed: bool) -> int:
    statuses = _provenance_statuses(retry_failed)
    row = conn.execute(
        f"""SELECT COUNT(1)
            FROM entries
            WHERE package_name IS NOT NULL
              AND provenance_status IN ({statuses})"""
    ).fetchone()
    return int(row[0]) if row else 0


def load_provenance_targets(conn: sqlite3.Connection, limit: int, retry_failed: bool) -> list[ProvenanceTarget]:
    statuses = _provenance_statuses(retry_failed)
    rows = conn.execute(
        f"""SELECT package_name, filename, sha256_digest
            FROM entries
            WHERE package_name IS NOT NULL
              AND provenance_status IN ({statuses})
            ORDER BY upload_time ASC, filename ASC, sha256_digest ASC
            LIMIT ?""",
        (limit,),
    ).fetchall()
    return [ProvenanceTarget(*row) for row in rows]


def update_package_provenance(
    conn: sqlite3.Connection,
    targets: list[ProvenanceTarget],
    ok: bool,
    prov_map: dict[str, Publisher | None],
    error: str | None,
):
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        for target in targets:
            pub = prov_map.get(target.filename)
            if ok:
                status = "found" if pub else "none"
                conn.execute(
                    """UPDATE entries
                       SET publisher_kind = ?, publisher_subject = ?,
                           provenance_status = ?, provenance_checked_at = ?, provenance_error = NULL
                       WHERE filename = ? AND sha256_digest = ?""",
                    (
                        pub.kind if pub else None,
                        pub.subject if pub else None,
                        status,
                        now,
                        target.filename,
                        target.sha256_digest,
                    ),
                )
            else:
                conn.execute(
                    """UPDATE entries
                       SET provenance_status = 'failed', provenance_checked_at = ?, provenance_error = ?
                       WHERE filename = ? AND sha256_digest = ?""",
                    (now, error, target.filename, target.sha256_digest),
                )


def run_provenance(args) -> None:
    conn = init_db(args.db)
    processed = found = none = failed = 0
    start = time.monotonic()
    progress_total = None
    if not args.no_count:
        CONSOLE.print("Counting provenance entries for progress ETA...")
        progress_total = count_provenance_targets(conn, args.retry_failed)
        if args.max_entries is not None:
            progress_total = min(progress_total, args.max_entries)
        CONSOLE.print(f"Entries to process this run: {progress_total}")

    def worker(pkg_name: str, pkg_targets: list[ProvenanceTarget]):
        client = httpx.Client(timeout=30, follow_redirects=True)
        try:
            names = {t.filename for t in pkg_targets}
            ok, prov_map, error = fetch_package_provenance(pkg_name, names, client)
            return pkg_name, ok, prov_map, error
        finally:
            client.close()
            time.sleep(WORKER_DELAY)

    with make_progress() as progress:
        task = progress.add_task("Fetching provenance", total=progress_total)
        while True:
            remaining = None if args.max_entries is None else args.max_entries - processed
            if remaining is not None and remaining <= 0:
                break
            limit = min(args.batch_size, remaining) if remaining is not None else args.batch_size
            targets = load_provenance_targets(conn, limit, args.retry_failed)
            if not targets:
                break
            grouped: dict[str, list[ProvenanceTarget]] = defaultdict(list)
            for target in targets:
                grouped[target.package_name].append(target)
            with ThreadPoolExecutor(max_workers=NUM_WORKERS) as pool:
                futures = {pool.submit(worker, pkg, pkg_targets): (pkg, pkg_targets) for pkg, pkg_targets in grouped.items()}
                for future in as_completed(futures):
                    pkg, pkg_targets = futures[future]
                    _, ok, prov_map, error = future.result()
                    update_package_provenance(conn, pkg_targets, ok, prov_map, error)
                    processed += len(pkg_targets)
                    if ok:
                        found += sum(1 for t in pkg_targets if prov_map.get(t.filename))
                        none += sum(1 for t in pkg_targets if not prov_map.get(t.filename))
                    else:
                        failed += len(pkg_targets)
                        log.warning("provenance failed for %s: %s", pkg, error)
                    progress.update(task, advance=len(pkg_targets))
    conn.close()
    CONSOLE.print(
        f"Done: processed={processed}, found={found}, none={none}, failed={failed}, elapsed={time.monotonic() - start:.1f}s"
    )


def build_add_url(log_url: str) -> str:
    return urljoin(log_url.rstrip("/") + "/", "add")


def entry_payload(entry: LogEntry) -> dict:
    payload = {"checksum": f"sha256:{entry.sha256_digest}", "filename": entry.filename}
    if entry.publisher:
        payload["publisher"] = {"kind": entry.publisher.kind, "subject": entry.publisher.subject}
    return payload


def is_logged(conn: sqlite3.Connection, filename: str, sha256_digest: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM logged_entries WHERE filename = ? AND sha256_digest = ?",
        (filename, sha256_digest),
    ).fetchone()
    return row is not None


def record_logged(conn: sqlite3.Connection, entry: LogEntry, log_index: int | None):
    logged_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO logged_entries (filename, sha256_digest, logged_at, log_index)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(filename, sha256_digest) DO UPDATE SET
             logged_at = excluded.logged_at,
             log_index = excluded.log_index""",
        (entry.filename, entry.sha256_digest, logged_at, str(log_index) if log_index is not None else None),
    )
    conn.commit()


def load_unlogged_entries(conn: sqlite3.Connection, max_entries: int | None = None) -> list[LogEntry]:
    limit = f" LIMIT {max_entries}" if max_entries else ""
    rows = conn.execute(
        """SELECT e.filename, e.sha256_digest, e.upload_time,
                  e.publisher_kind, e.publisher_subject
           FROM entries e
           LEFT JOIN logged_entries l
             ON l.filename = e.filename AND l.sha256_digest = e.sha256_digest
           WHERE l.filename IS NULL
             AND e.provenance_status IN ('found', 'none')
           ORDER BY e.upload_time ASC, e.filename ASC, e.sha256_digest ASC""" + limit
    ).fetchall()
    entries = []
    for filename, digest, upload_time, pub_kind, pub_subject in rows:
        publisher = Publisher(pub_kind, pub_subject) if pub_kind and pub_subject else None
        entries.append(LogEntry(filename, digest, upload_time, publisher))
    return entries


def submit_entry(
    client: httpx.Client,
    add_url: str,
    entry: LogEntry,
    max_retries: int,
    retry_backoff: float,
) -> int | None:
    payload = entry_payload(entry)
    for attempt in range(max_retries):
        try:
            resp = client.post(add_url, json=payload)
            body = resp.text
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    data = {}
                return data.get("index")
            if 400 <= resp.status_code < 500:
                raise RuntimeError(f"bt-log rejected {entry.filename}: {resp.status_code} {body}")
            raise httpx.HTTPStatusError(
                f"bt-log returned {resp.status_code}: {body}",
                request=resp.request,
                response=resp,
            )
        except (httpx.HTTPError, RuntimeError) as e:
            if isinstance(e, RuntimeError) or attempt == max_retries - 1:
                raise
            wait = retry_backoff * (2 ** attempt)
            log.warning(
                "submit failed for %s (attempt %d/%d): %s; retrying in %.1fs",
                entry.filename,
                attempt + 1,
                max_retries,
                e,
                wait,
            )
            time.sleep(wait)
    raise RuntimeError("unreachable")


def run_submit(args) -> None:
    conn = init_db(args.db)
    entries = load_unlogged_entries(conn, args.max_submit)
    if not entries:
        CONSOLE.print("No unlogged entries to submit")
        conn.close()
        return
    add_url = build_add_url(args.log_url)
    CONSOLE.print(f"Submitting {len(entries)} entries to {add_url}")
    succeeded = failed = 0
    with make_progress() as progress:
        task = progress.add_task("Submitting entries", total=len(entries))
        with httpx.Client(timeout=args.timeout) as client:
            for entry in entries:
                if is_logged(conn, entry.filename, entry.sha256_digest):
                    progress.update(task, advance=1)
                    continue
                try:
                    index = submit_entry(client, add_url, entry, args.retries, args.retry_backoff)
                except Exception as e:
                    failed += 1
                    log.error("failed to submit %s: %s", entry.filename, e)
                    progress.update(task, advance=1)
                    continue
                record_logged(conn, entry, index)
                succeeded += 1
                progress.update(task, advance=1)
                if succeeded % 25 == 0:
                    log.info("submitted %d/%d entries", succeeded, len(entries))
    conn.close()
    CONSOLE.print(f"Done: submitted={succeeded}, submit_failed={failed}")


def _since_to_upload_time(since: str | None) -> str | None:
    if not since:
        return None
    try:
        return _normalize_upload_time(since)
    except Exception:
        pass
    dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _normalize_upload_time(str(dt.timestamp()))


def main():
    args = parse_args()
    logging.getLogger().setLevel(args.log_level.upper())
    # httpx logs every request at INFO, which breaks Rich's live progress display.
    # Keep third-party HTTP logs quiet unless explicitly debugging them in code.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if args.command == "bigquery":
        run_bigquery(args)
    elif args.command == "provenance":
        run_provenance(args)
    elif args.command == "submit":
        run_submit(args)
    else:
        raise RuntimeError(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
