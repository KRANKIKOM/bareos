"""
Read-only catalog access for list endpoints that would otherwise go through
the director console (`llist jobs`).

Why: the director answers every `llist jobs` with one SQL query behind its
single, locked catalog connection and serialises the result as JSON over the
console — for a dashboard that fetches the job list on nearly every page this
was the slowest call (~0.5 s and growing with the job history).

Contract: the rows are exactly what `llist jobs` returns in API mode 2 — same
keys, same order, every value the PostgreSQL text rendering of the column
(the director prints libpq text values), NULL as "". The query is the
director's own list_jobs_long (core/src/cats/dml/0007_list_jobs_long) minus the
JobMedia/Media joins, which only serve the volume filter: without that filter
they multiply rows that DISTINCT collapses again, so the result is identical.

Only used for schema versions listed in [Catalog] SchemaVersions (default
2250, Bareos 23-25); anything else falls back to the console.
"""

import threading

try:
    import psycopg
except ImportError:  # optional dependency: no catalog path without it
    psycopg = None

JOB_COLUMNS = (
    "jobid", "job", "name", "purgedfiles", "type", "level", "clientid", "client",
    "jobstatus", "schedtime", "starttime", "endtime", "realendtime", "duration",
    "jobtdate", "volsessionid", "volsessiontime", "jobfiles", "jobbytes",
    "joberrors", "jobmissingfiles", "poolid", "poolname", "priorjobid",
    "filesetid", "fileset",
)

_JOB_EXPR = {
    "jobid": "Job.JobId",
    "job": "Job.Job",
    "name": "Job.Name",
    "purgedfiles": "Job.PurgedFiles",
    "type": "Job.Type",
    "level": "Job.Level",
    "clientid": "Job.ClientId",
    "client": "Client.Name",
    "jobstatus": "Job.JobStatus",
    "schedtime": "Job.SchedTime",
    "starttime": "Job.StartTime",
    "endtime": "Job.EndTime",
    "realendtime": "Job.RealEndtime",
    "duration": (
        "CASE WHEN Job.endtime IS NOT NULL AND Job.endtime >= Job.starttime "
        "THEN Job.endtime - Job.starttime "
        "ELSE CURRENT_TIMESTAMP(0) - Job.starttime END"
    ),
    "jobtdate": "Job.JobTDate",
    "volsessionid": "Job.VolSessionId",
    "volsessiontime": "Job.VolSessionTime",
    "jobfiles": "Job.JobFiles",
    "jobbytes": "Job.JobBytes",
    "joberrors": "Job.JobErrors",
    "jobmissingfiles": "Job.JobMissingFiles",
    "poolid": "Job.PoolId",
    "poolname": "Pool.Name",
    "priorjobid": "Job.PriorJobId",
    "filesetid": "Job.FileSetId",
    "fileset": "FileSet.FileSet",
}

LIST_JOBS_SQL = (
    "SELECT "
    + ", ".join("COALESCE((%s)::text, '') AS %s" % (_JOB_EXPR[c], c) for c in JOB_COLUMNS)
    + " FROM Job"
    " LEFT JOIN Client ON Client.ClientId=Job.ClientId"
    " LEFT JOIN Pool ON Pool.PoolId=Job.PoolId"
    " LEFT JOIN FileSet ON FileSet.FileSetId=Job.FileSetId"
    " WHERE Job.JobId > 0"
    # The director's DISTINCT ends up ordered by JobId among equal start
    # times; say so explicitly.
    " ORDER BY Job.StartTime, Job.JobId"
)

COUNT_JOBS_SQL = "SELECT COUNT(*)::text FROM Job WHERE Job.JobId > 0"


class Catalog(object):
    """Short-lived read-only connections to the director's catalog."""

    def __init__(self, host, port, dbname, user, password, schema_versions, connect_timeout=3):
        self._params = dict(
            host=host, port=port, dbname=dbname, user=user, password=password,
            connect_timeout=connect_timeout, application_name="bareos-restapi",
        )
        self._schema_versions = set(schema_versions)
        self._checked = None  # None = not yet, True/False = schema usable
        self._lock = threading.Lock()

    def _connect(self):
        conn = psycopg.connect(autocommit=True, **self._params)
        conn.read_only = True
        return conn

    def usable(self):
        """True once the catalog answered with a known schema version."""
        if psycopg is None:
            return False
        with self._lock:
            if self._checked is None:
                try:
                    with self._connect() as conn:
                        row = conn.execute("SELECT max(VersionId) FROM Version").fetchone()
                    version = row[0] if row else None
                    self._checked = version in self._schema_versions
                    if not self._checked:
                        print(
                            "[catalog] schema version %s not in %s, using the console"
                            % (version, sorted(self._schema_versions))
                        )
                except Exception as e:
                    # Not cached: a catalog that is down now may answer later.
                    print("[catalog] not reachable (%s), using the console" % e)
                    return False
            return self._checked

    def list_jobs(self, limit=None, offset=None):
        """(totalItems, rows) like `llist jobs [limit=…] [offset=…]` + its count."""
        sql = LIST_JOBS_SQL
        args = []
        if limit is not None:
            sql += " LIMIT %s"
            args.append(int(limit))
        if offset is not None:
            sql += " OFFSET %s"
            args.append(int(offset))
        with self._connect() as conn:
            cur = conn.execute(sql, args)
            rows = [dict(zip(JOB_COLUMNS, r)) for r in cur.fetchall()]
            if limit is None and offset is None:
                total = str(len(rows))
            else:
                total = conn.execute(COUNT_JOBS_SQL).fetchone()[0]
        return total, rows
