# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptography",
#     "google-auth",
#     "httpx",
#     "requests",
# ]
# ///
"""Sync PyPI distribution metadata from BigQuery into a local
SQLite database with provenance from the PyPI Simple API."""

import argparse
import base64
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
import httpx
from cryptography import x509

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.WARNING)
log = logging.getLogger(__name__)

NUM_WORKERS = 10
WORKER_DELAY = 0.25
BQ_PAGE_SIZE = 100000


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


def parse_args():
    p = argparse.ArgumentParser(
        description="Sync PyPI metadata from BigQuery to SQLite and optionally submit to bt-log",
    )
    p.add_argument(
        "--db",
        default=os.environ.get("PYPI_INGEST_DB", "pypi_entries.db"),
        help="path to SQLite database (default: $PYPI_INGEST_DB or pypi_entries.db)",
    )
    p.add_argument(
        "--log-url",
        default=os.environ.get("BT_LOG_URL", "http://localhost:8080"),
        help="base URL of bt-log (default: $BT_LOG_URL or http://localhost:8080)",
    )
    p.add_argument(
        "--submit",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="submit unlogged entries to bt-log /add (default: false)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("PYPI_INGEST_TIMEOUT", "30")),
        help="HTTP timeout in seconds for bt-log submissions (default: 30)",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=int(os.environ.get("PYPI_INGEST_RETRIES", "3")),
        help="maximum bt-log submission attempts (default: 3)",
    )
    p.add_argument(
        "--retry-backoff",
        type=float,
        default=float(os.environ.get("PYPI_INGEST_RETRY_BACKOFF", "1")),
        help="initial submission retry backoff in seconds (default: 1)",
    )
    p.add_argument(
        "--since",
        help=(
            "initial BigQuery lower bound when no cursor exists; accepts Unix "
            "seconds or ISO/RFC3339 timestamp"
        ),
    )
    p.add_argument(
        "--max-rows",
        type=int,
        help="maximum BigQuery rows to fetch in this run",
    )
    p.add_argument(
        "--max-submit",
        type=int,
        help="maximum unlogged SQLite entries to submit in this run",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("PYPI_INGEST_LOG_LEVEL", "INFO"),
        help="Python logging level (default: INFO)",
    )
    return p.parse_args()


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            filename          TEXT NOT NULL,
            sha256_digest     TEXT NOT NULL,
            publisher_kind    TEXT,
            publisher_subject TEXT,
            upload_time       TEXT NOT NULL,
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
    conn.commit()
    return conn


def get_cursor(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT value FROM cursor WHERE key = 'last_upload_time'"
    ).fetchone()
    return row[0] if row else None


def set_cursor(conn: sqlite3.Connection, upload_time: str):
    conn.execute(
        """INSERT INTO cursor (key, value) VALUES
        ('last_upload_time', ?)
        ON CONFLICT(key) DO UPDATE SET value = ?""",
        (upload_time, upload_time),
    )
    conn.commit()


def get_bq_auth() -> tuple[str, str]:
    """Return (access_token, project_id) from ADC."""
    try:
        creds, project = google.auth.default(scopes=BQ_SCOPES)
        creds.refresh(google.auth.transport.requests.Request())
    except google.auth.exceptions.DefaultCredentialsError as e:
        if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            print(
                "Google Application Default Credentials were not found.\n"
                "Fix this by running:\n"
                "  gcloud auth application-default login\n"
                "  gcloud config set project PROJECT_ID\n"
                "\n"
                "Or use a service account key:\n"
                "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json\n"
                "  export GOOGLE_CLOUD_PROJECT=PROJECT_ID",
                file=sys.stderr,
            )
        raise SystemExit(f"Unable to authenticate with Google Cloud: {e}") from None
    except google.auth.exceptions.RefreshError as e:
        print(
            "Google Cloud credentials were found, but refreshing the access token failed.\n"
            "This script requests the cloud-platform OAuth scope for BigQuery.\n"
            "Try refreshing ADC with:\n"
            "  gcloud auth application-default login \\\n"
            "    --scopes=https://www.googleapis.com/auth/cloud-platform\n"
            "  gcloud config set project PROJECT_ID\n"
            "\n"
            "If using a service account, make sure GOOGLE_APPLICATION_CREDENTIALS points "
            "to a service account JSON key, not an ID-token/audience credential file.",
            file=sys.stderr,
        )
        raise SystemExit(f"Unable to refresh Google Cloud credentials: {e}") from None
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
        raise RuntimeError(
            "No GCP projects found. Set a default project with: "
            "gcloud config set project PROJECT_ID"
        )
    return projects[0]["projectId"]


def print_progress(
    current: int,
    total: int,
    start: float,
    label: str = "rows",
):
    if total == 0:
        return
    pct = current / total * 100
    bar_width = 30
    filled = int(bar_width * current / total)
    bar = "=" * filled + " " * (bar_width - filled)
    eta = "..."
    if current > 0:
        elapsed = time.monotonic() - start
        rate = current / elapsed
        remaining = (total - current) / rate
        eta = f"{remaining:.0f}s"
    sys.stderr.write(f"\r[{bar}] {current}/{total} {label} ({pct:.1f}%) ETA: {eta}   ")
    sys.stderr.flush()


BQ_BASE = "https://bigquery.googleapis.com/bigquery/v2/projects"
BQ_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def query_bigquery(
    token: str,
    project: str,
    last_upload_time: str | None,
    max_rows: int | None = None,
) -> list[dict]:
    """Query BigQuery and return all rows as dicts."""
    where = "WHERE sha256_digest IS NOT NULL"
    if last_upload_time:
        micros = int(float(last_upload_time) * 1_000_000)
        where += f"\n              AND upload_time >= TIMESTAMP_MICROS({micros})"
    limit = f"\n            LIMIT {max_rows}" if max_rows else ""
    query = f"""
            SELECT name, filename, sha256_digest, upload_time
            FROM `bigquery-public-data.pypi.distribution_metadata`
            {where}
            ORDER BY upload_time ASC{limit}
        """

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Start the query job
    resp = _bq_request(
        "POST",
        f"{BQ_BASE}/{project}/queries",
        headers=headers,
        json_body={
            "query": query,
            "useLegacySql": False,
            "maxResults": BQ_PAGE_SIZE,
        },
    )
    data = resp

    job_id = data["jobReference"]["jobId"]

    # Wait for job to complete
    while not data.get("jobComplete"):
        time.sleep(2)
        data = _bq_request(
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            headers=headers,
            params={"maxResults": BQ_PAGE_SIZE},
        )

    total = int(data.get("totalRows", 0))
    fields = [f["name"] for f in data["schema"]["fields"]]
    rows = []
    start = time.monotonic()

    # Collect first page
    for row in data.get("rows", []):
        values = [cell["v"] for cell in row["f"]]
        rows.append(dict(zip(fields, values)))
    print_progress(len(rows), total, start)

    # Paginate
    page_token = data.get("pageToken")
    while page_token:
        data = _bq_request(
            "GET",
            f"{BQ_BASE}/{project}/queries/{job_id}",
            headers=headers,
            params={"maxResults": BQ_PAGE_SIZE, "pageToken": page_token},
        )
        for row in data.get("rows", []):
            values = [cell["v"] for cell in row["f"]]
            rows.append(dict(zip(fields, values)))
        print_progress(len(rows), total, start)
        page_token = data.get("pageToken")

    sys.stderr.write("\n")
    sys.stderr.flush()
    print(f"Fetched {len(rows)} rows from BigQuery", flush=True)
    return rows


def _bq_request(
    method: str,
    url: str,
    headers: dict,
    json_body: dict | None = None,
    params: dict | None = None,
    max_retries: int = 3,
) -> dict:
    """HTTP request to BigQuery with retry and backoff."""
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=120) as client:
                resp = client.request(
                    method,
                    url,
                    headers=headers,
                    json=json_body,
                    params=params,
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            if attempt == max_retries - 1:
                raise
            wait = 2 ** (attempt + 1)
            print(
                f"\nBigQuery request failed: {e}. Retrying in {wait}s...",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(wait)
    raise RuntimeError("unreachable")


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


def load_etag_cache(path: str) -> dict[str, str]:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_etag_cache(path: str, cache: dict[str, str]):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, path)


def fetch_package_provenance(
    pkg_name: str,
    filenames: set[str],
    etag: str | None,
    client: httpx.Client,
) -> tuple[dict[str, Publisher | None], str | None]:
    """Fetch provenance for files in a package.

    Returns (filename->publisher map, new_etag).
    """
    url = f"https://pypi.org/simple/{pkg_name}/"
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    if etag:
        headers["If-None-Match"] = etag

    try:
        resp = client.get(url, headers=headers)
    except httpx.HTTPError:
        log.warning("Failed to fetch simple API for %s", pkg_name)
        return {}, None

    if resp.status_code == 304:
        return {}, etag

    if resp.status_code != 200:
        log.warning("Simple API %s returned %s", pkg_name, resp.status_code)
        return {}, None

    new_etag = resp.headers.get("ETag")

    try:
        data = resp.json()
    except Exception:
        log.warning("Failed to parse simple API JSON for %s", pkg_name)
        return {}, new_etag

    result: dict[str, Publisher | None] = {}
    for f in data.get("files", []):
        fname = f.get("filename", "")
        if fname not in filenames:
            continue
        prov_url = f.get("provenance")
        if not prov_url:
            result[fname] = None
            continue
        result[fname] = _fetch_provenance_bundle(fname, prov_url, client)

    return result, new_etag


def _fetch_provenance_bundle(
    filename: str, prov_url: str, client: httpx.Client
) -> Publisher | None:
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


def fetch_all_provenance(
    rows: list[dict],
    etag_cache: dict[str, str],
) -> list[LogEntry]:
    """Fetch provenance for all packages and return LogEntry list."""
    # Group by package name
    pkg_files: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        pkg_files[row["name"]].add(row["filename"])

    packages = list(pkg_files.keys())
    total = len(packages)
    print(f"Fetching provenance for {total} packages", flush=True)

    # filename -> Publisher mapping built up by workers
    publishers: dict[str, Publisher | None] = {}
    completed = 0
    skipped = 0
    start = time.monotonic()

    def worker(pkg_name: str) -> tuple[str, dict, str | None, bool]:
        client = httpx.Client(timeout=30)
        try:
            prov_map, new_etag = fetch_package_provenance(
                pkg_name,
                pkg_files[pkg_name],
                etag_cache.get(pkg_name),
                client,
            )
            was_skipped = not prov_map and new_etag == etag_cache.get(pkg_name)
            return pkg_name, prov_map, new_etag, was_skipped
        finally:
            client.close()
            time.sleep(WORKER_DELAY)

    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as pool:
        futures = {pool.submit(worker, pkg): pkg for pkg in packages}
        for future in as_completed(futures):
            pkg_name, prov_map, new_etag, was_skipped = future.result()
            publishers.update(prov_map)
            if new_etag:
                etag_cache[pkg_name] = new_etag
            completed += 1
            if was_skipped:
                skipped += 1
            if completed % 10 == 0 or completed == total:
                print_progress(
                    completed,
                    total,
                    start,
                    label=f"pkgs {skipped} skipped",
                )

    sys.stderr.write("\n")
    sys.stderr.flush()

    # Build final entries
    entries = []
    for row in rows:
        pub = publishers.get(row["filename"])
        entries.append(
            LogEntry(
                filename=row["filename"],
                sha256_digest=row["sha256_digest"],
                upload_time=row["upload_time"],
                publisher=pub,
            )
        )
    return entries


def insert_entries(conn: sqlite3.Connection, entries: list[LogEntry]):
    """Insert entries into SQLite, skipping duplicates."""
    inserted = 0
    for entry in entries:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO entries
                (filename, sha256_digest, publisher_kind,
                 publisher_subject, upload_time)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    entry.filename,
                    entry.sha256_digest,
                    entry.publisher.kind if entry.publisher else None,
                    (entry.publisher.subject if entry.publisher else None),
                    entry.upload_time,
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0] > 0:
                inserted += 1
        except sqlite3.Error:
            log.warning("Failed to insert %s", entry.filename)
    conn.commit()
    return inserted


def build_add_url(log_url: str) -> str:
    return urljoin(log_url.rstrip("/") + "/", "add")


def entry_payload(entry: LogEntry) -> dict:
    payload = {
        "checksum": f"sha256:{entry.sha256_digest}",
        "filename": entry.filename,
    }
    if entry.publisher:
        payload["publisher"] = {
            "kind": entry.publisher.kind,
            "subject": entry.publisher.subject,
        }
    return payload


def is_logged(conn: sqlite3.Connection, filename: str, sha256_digest: str) -> bool:
    row = conn.execute(
        """SELECT 1 FROM logged_entries
        WHERE filename = ? AND sha256_digest = ?""",
        (filename, sha256_digest),
    ).fetchone()
    return row is not None


def record_logged(
    conn: sqlite3.Connection,
    entry: LogEntry,
    log_index: int | None,
):
    logged_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO logged_entries
        (filename, sha256_digest, logged_at, log_index)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(filename, sha256_digest) DO UPDATE SET
            logged_at = excluded.logged_at,
            log_index = excluded.log_index""",
        (entry.filename, entry.sha256_digest, logged_at, str(log_index) if log_index is not None else None),
    )
    conn.commit()


def load_unlogged_entries(
    conn: sqlite3.Connection,
    max_entries: int | None = None,
) -> list[LogEntry]:
    limit = f" LIMIT {max_entries}" if max_entries else ""
    rows = conn.execute(
        """SELECT e.filename, e.sha256_digest, e.upload_time,
                  e.publisher_kind, e.publisher_subject
           FROM entries e
           LEFT JOIN logged_entries l
             ON l.filename = e.filename AND l.sha256_digest = e.sha256_digest
           WHERE l.filename IS NULL
           ORDER BY e.upload_time ASC""" + limit
    ).fetchall()
    entries = []
    for filename, digest, upload_time, pub_kind, pub_subject in rows:
        publisher = None
        if pub_kind and pub_subject:
            publisher = Publisher(kind=pub_kind, subject=pub_subject)
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
                raise RuntimeError(
                    f"bt-log rejected {entry.filename}: {resp.status_code} {body}"
                )
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


def submit_unlogged_entries(
    conn: sqlite3.Connection,
    log_url: str,
    timeout: float,
    retries: int,
    retry_backoff: float,
    max_submit: int | None = None,
) -> tuple[int, int]:
    entries = load_unlogged_entries(conn, max_submit)
    if not entries:
        print("No unlogged entries to submit", flush=True)
        return 0, 0

    add_url = build_add_url(log_url)
    print(f"Submitting {len(entries)} entries to {add_url}", flush=True)
    succeeded = 0
    failed = 0
    with httpx.Client(timeout=timeout) as client:
        for entry in entries:
            if is_logged(conn, entry.filename, entry.sha256_digest):
                continue
            try:
                index = submit_entry(client, add_url, entry, retries, retry_backoff)
            except Exception as e:
                failed += 1
                log.error("failed to submit %s: %s", entry.filename, e)
                continue
            record_logged(conn, entry, index)
            succeeded += 1
            if succeeded % 25 == 0:
                log.info("submitted %d/%d entries", succeeded, len(entries))
    return succeeded, failed


def _since_to_upload_time(since: str | None) -> str | None:
    if not since:
        return None
    try:
        return str(float(since))
    except ValueError:
        pass
    dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return str(dt.timestamp())


def main():
    args = parse_args()
    logging.getLogger().setLevel(args.log_level.upper())
    conn = init_db(args.db)
    last_upload_time = get_cursor(conn)
    query_start = last_upload_time or _since_to_upload_time(args.since)
    if last_upload_time:
        print(f"Resuming from cursor {last_upload_time}", flush=True)
    elif query_start:
        print(f"First run: fetching entries since {query_start}", flush=True)
    else:
        print("First run: fetching all entries", flush=True)

    token, project = get_bq_auth()
    print(f"Using project: {project}", flush=True)

    rows = query_bigquery(token, project, query_start, args.max_rows)
    if rows:
        etag_path = args.db + ".etags"
        etag_cache = load_etag_cache(etag_path)
        print(f"Loaded {len(etag_cache)} cached ETags", flush=True)

        entries = fetch_all_provenance(rows, etag_cache)

        print("Inserting entries into SQLite...", flush=True)
        inserted = insert_entries(conn, entries)

        # Update cursor to the max upload_time we saw. This is independent of
        # submission state; unsubmitted rows stay in SQLite and are retried by
        # submit_unlogged_entries on later runs.
        max_upload_time = max(e.upload_time for e in entries)
        set_cursor(conn, max_upload_time)

        save_etag_cache(etag_path, etag_cache)
        print(
            f"Synced: {inserted} new entries inserted, "
            f"{len(entries) - inserted} duplicates skipped",
            flush=True,
        )
    else:
        print("No new entries found", flush=True)

    submitted = failed = 0
    if args.submit:
        submitted, failed = submit_unlogged_entries(
            conn,
            args.log_url,
            args.timeout,
            args.retries,
            args.retry_backoff,
            args.max_submit,
        )
    else:
        print("Submission disabled; use --submit to POST entries to bt-log", flush=True)

    conn.close()
    print(
        f"Done: submitted={submitted}, submit_failed={failed}",
        flush=True,
    )


if __name__ == "__main__":
    main()
