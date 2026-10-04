-- A run can stop because its session expired, and the record has to be able to say so.
--
-- `scan_runs.stopped_because` was constrained to ('cancelled', 'ceiling') in 0008, before
-- `StoppedBecause::CredentialExpired` existed. When an active run now stops because the
-- identity's credential expired mid-run, writing its record failed the CHECK constraint
-- and the whole run errored out — the one outcome that most needs recording, lost.
--
-- SQLite cannot alter a CHECK constraint in place, so the table is rebuilt with the
-- constraint widened to include 'credential_expired'. Foreign keys are on and migrations
-- run in a transaction (so the pragma cannot be toggled here), which means the child table
-- `scan_run_detectors` is copied aside and dropped first — a parent DROP with its child
-- still present would cascade-delete the detector rows. Everything is restored afterwards;
-- existing `stopped_because` values ('cancelled', 'ceiling', NULL) all satisfy the wider
-- constraint.

CREATE TABLE _scan_runs_backup AS SELECT * FROM scan_runs;
CREATE TABLE _scan_run_detectors_backup AS SELECT * FROM scan_run_detectors;

DROP TABLE scan_run_detectors;
DROP TABLE scan_runs;

CREATE TABLE scan_runs (
    id                TEXT PRIMARY KEY,
    selection         TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL,
    completed_at      TEXT,
    status            TEXT NOT NULL DEFAULT 'running'
                          CHECK (status IN ('running', 'completed', 'failed')),
    exchanges_read    INTEGER NOT NULL DEFAULT 0,
    exchanges_skipped INTEGER NOT NULL DEFAULT 0,
    tool_version      TEXT NOT NULL,
    requests_sent     INTEGER NOT NULL DEFAULT 0,
    stopped_because   TEXT
                          CHECK (stopped_because IN ('cancelled', 'ceiling', 'credential_expired'))
);

CREATE INDEX idx_scan_runs_started_at ON scan_runs(started_at DESC);

CREATE TABLE scan_run_detectors (
    run_id           TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    detector_id      TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    mode             TEXT NOT NULL CHECK (mode IN ('passive', 'active')),
    observations     INTEGER NOT NULL DEFAULT 0,
    hypotheses       INTEGER NOT NULL DEFAULT 0,
    reportable       INTEGER NOT NULL DEFAULT 0,
    -- Added in 0010; carried through the rebuild so the record keeps saying why a
    -- programme did not accept what a detector found.
    excluded_reason  TEXT,
    PRIMARY KEY (run_id, detector_id)
);

INSERT INTO scan_runs (
    id, selection, started_at, completed_at, status,
    exchanges_read, exchanges_skipped, tool_version, requests_sent, stopped_because
)
SELECT
    id, selection, started_at, completed_at, status,
    exchanges_read, exchanges_skipped, tool_version, requests_sent, stopped_because
FROM _scan_runs_backup;

INSERT INTO scan_run_detectors (
    run_id, detector_id, detector_version, mode, observations, hypotheses, reportable, excluded_reason
)
SELECT
    run_id, detector_id, detector_version, mode, observations, hypotheses, reportable, excluded_reason
FROM _scan_run_detectors_backup;

DROP TABLE _scan_run_detectors_backup;
DROP TABLE _scan_runs_backup;
