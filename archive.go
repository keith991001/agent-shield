//go:build linux

package main

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// AlertArchive persists alert/block events to SQLite. This is distinct
// from EventHistory (in-memory ring buffer) — the archive survives
// daemon restarts and lets the investigator agent query historical
// behavior per PID across sessions.
//
// Concurrency: SQLite (modernc driver) handles multi-goroutine writes
// via internal serialization. We add no extra locking on top.
type AlertArchive struct {
	db   *sql.DB
	once sync.Once
}

const archiveSchema = `
CREATE TABLE IF NOT EXISTS alerts (
    rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL,
    timestamp   TEXT    NOT NULL,
    pid         INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    comm        TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    path        TEXT,
    dest        TEXT,
    rule        TEXT,
    action      TEXT,
    severity    TEXT,
    risk        INTEGER,
    risk_cat    TEXT,
    risk_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_pid  ON alerts(pid);
CREATE INDEX IF NOT EXISTS idx_alerts_comm ON alerts(comm);
CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(timestamp);
`

// OpenAlertArchive opens (or creates) a SQLite database file at path.
// Use ":memory:" for an ephemeral archive (mostly useful in tests).
func OpenAlertArchive(path string) (*AlertArchive, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	if _, err := db.Exec(archiveSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Sensible SQLite tuning for this workload (mostly writes, occasional
	// query). WAL gives better concurrent-read behavior with the lone writer.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}
	return &AlertArchive{db: db}, nil
}

func (a *AlertArchive) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	return a.db.Close()
}

// Record persists an event. Only matched events (rule != "") are
// recorded — the noise events are not worth the disk write.
func (a *AlertArchive) Record(e *Event) error {
	if a == nil || e.Rule == "" {
		return nil
	}
	_, err := a.db.Exec(
		`INSERT INTO alerts
		  (event_id, timestamp, pid, uid, comm, type, path, dest,
		   rule, action, severity, risk, risk_cat, risk_reason)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.Time, e.PID, e.UID, e.Comm, e.Type, e.Path, e.Dest,
		e.Rule, string(e.Action), string(e.Severity), e.Risk, e.RiskCategory, e.RiskReason,
	)
	return err
}

// PIDProfile is the aggregate summary the investigator agent's
// get_pid_history tool returns.
type PIDProfile struct {
	PID            uint32
	TotalAlerts    int
	TotalBlocks    int
	AvgRisk        float64
	MaxRisk        int
	Categories     []string // distinct categories observed
	LastSeen       string   // most recent event timestamp
	LastTwoReasons []string // most recent two risk_reason strings
}

// ProfileForPID looks up a PID's historical behavior. Returns nil
// (no error) if there are no prior records.
func (a *AlertArchive) ProfileForPID(pid uint32) (*PIDProfile, error) {
	if a == nil {
		return nil, nil
	}

	p := &PIDProfile{PID: pid}

	// Aggregate counts and stats.
	row := a.db.QueryRow(
		`SELECT
		   COUNT(*),
		   COALESCE(SUM(CASE WHEN action='block' THEN 1 ELSE 0 END), 0),
		   COALESCE(AVG(risk), 0),
		   COALESCE(MAX(risk), 0),
		   COALESCE(MAX(timestamp), '')
		 FROM alerts WHERE pid = ?`, pid)

	if err := row.Scan(&p.TotalAlerts, &p.TotalBlocks, &p.AvgRisk, &p.MaxRisk, &p.LastSeen); err != nil {
		return nil, err
	}
	if p.TotalAlerts == 0 {
		return nil, nil
	}

	// Distinct categories.
	rows, err := a.db.Query(`SELECT DISTINCT risk_cat FROM alerts WHERE pid = ? AND risk_cat != ''`, pid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err == nil {
			p.Categories = append(p.Categories, c)
		}
	}
	_ = rows.Close()

	// Last two reasons (most recent).
	rows, err = a.db.Query(
		`SELECT risk_reason FROM alerts
		 WHERE pid = ? AND risk_reason != ''
		 ORDER BY rowid DESC LIMIT 2`, pid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err == nil {
			p.LastTwoReasons = append(p.LastTwoReasons, r)
		}
	}
	_ = rows.Close()

	return p, nil
}

// Format returns a compact human-readable summary suitable for an LLM
// tool result.
func (p *PIDProfile) Format() string {
	if p == nil {
		return "no prior alert history for this PID"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pid=%d total_alerts=%d total_blocks=%d avg_risk=%.1f max_risk=%d last_seen=%s",
		p.PID, p.TotalAlerts, p.TotalBlocks, p.AvgRisk, p.MaxRisk, p.LastSeen)
	if len(p.Categories) > 0 {
		fmt.Fprintf(&b, " categories=[%s]", strings.Join(p.Categories, ","))
	}
	if len(p.LastTwoReasons) > 0 {
		fmt.Fprintf(&b, "\nmost recent reasons:\n")
		for i, r := range p.LastTwoReasons {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, r)
		}
	}
	return b.String()
}

// CountSinceTime returns how many alerts the entire archive contains
// in the last N seconds (useful for "is this a busy time?" context).
func (a *AlertArchive) CountSinceTime(seconds int) (int, error) {
	if a == nil {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339Nano)
	row := a.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE timestamp > ?`, cutoff)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
