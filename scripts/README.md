# Scripts

## `query_pypi_bigquery.py`

Syncs PyPI distribution metadata into a local SQLite database, enriches it with PyPI provenance information, and submits processed entries to `bt-log`.

The script has three resumable commands:

```bash
uv run scripts/query_pypi_bigquery.py bigquery
uv run scripts/query_pypi_bigquery.py provenance
uv run scripts/query_pypi_bigquery.py submit
```

Each command commits progress incrementally, so it is safe to stop and run again later.

## Setup

Authenticate Google Application Default Credentials with access to BigQuery:

```bash
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/bigquery.readonly,https://www.googleapis.com/auth/cloud-platform.read-only
```

Optionally set a default project:

```bash
gcloud config set project PROJECT_ID
```

## Database

By default, the SQLite database is:

```bash
pypi_entries.db
```

Override it with:

```bash
--db path/to/pypi.db
```

or:

```bash
export PYPI_INGEST_DB=path/to/pypi.db
```

## 1. Ingest BigQuery rows

Populate the database with raw PyPI file metadata:

```bash
uv run scripts/query_pypi_bigquery.py bigquery --db pypi.db
```

This stores package name, filename, SHA-256 digest, and upload time.

Useful options:

```bash
--since 2024-01-01T00:00:00Z
--batch-size 50000
--max-rows 1000000
--no-count
```

The command uses a durable cursor and resumes from the last committed BigQuery row.

## 2. Fetch provenance

Enrich unchecked database entries with PyPI provenance information:

```bash
uv run scripts/query_pypi_bigquery.py provenance --db pypi.db
```

Each processed entry is marked as:

- `found` — provenance/publisher was found
- `none` — checked, but no provenance exists
- `failed` — provenance lookup failed

Rows marked `found` or `none` are skipped on future provenance runs.

Useful options:

```bash
--batch-size 5000
--max-entries 100000
--retry-failed
--no-count
```

## 3. Submit to bt-log

Submit processed, unlogged entries to `bt-log`:

```bash
uv run scripts/query_pypi_bigquery.py submit \
  --db pypi.db \
  --log-url http://localhost:8080
```

Only entries with provenance status `found` or `none` are submitted. Entries that are still `unchecked` or `failed` are skipped.

After a successful submission, the entry is recorded in `logged_entries`, so later runs resume where they left off.

Useful options:

```bash
--max-submit 10000
--timeout 30
--retries 3
--retry-backoff 1
```

You can also set:

```bash
export BT_LOG_URL=http://localhost:8080
```

## Typical workflow

```bash
uv run scripts/query_pypi_bigquery.py bigquery --db pypi.db
uv run scripts/query_pypi_bigquery.py provenance --db pypi.db
uv run scripts/query_pypi_bigquery.py submit --db pypi.db --log-url http://localhost:8080
```

Run the same commands again later to ingest new BigQuery rows, process new provenance entries, and submit newly processed entries.
