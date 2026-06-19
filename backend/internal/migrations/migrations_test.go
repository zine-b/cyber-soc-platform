package migrations

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteMigrationsAreVersionedAndIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	if err := Up(db, SQLite); err != nil {
		t.Fatalf("run first migration: %v", err)
	}
	if err := Up(db, SQLite); err != nil {
		t.Fatalf("run migrations a second time: %v", err)
	}

	for _, table := range []string{"logs", "alerts", "incidents", "schema_migrations"} {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count)
		if err != nil {
			t.Fatalf("query table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("expected table %s to exist", table)
		}
	}

	var version int
	var dirty bool
	if err := db.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("unexpected migration state: version=%d dirty=%v", version, dirty)
	}
}

func TestSQLiteMigrationsAdoptExistingSchema(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	legacySchema := `
		CREATE TABLE logs (id INTEGER PRIMARY KEY, source VARCHAR, log_type VARCHAR, message VARCHAR, parsed JSON, received_at DATETIME);
		CREATE TABLE alerts (id INTEGER PRIMARY KEY, rule_id VARCHAR, incident_id INTEGER, title VARCHAR, description VARCHAR, severity VARCHAR, source_ip VARCHAR, failed_attempts INTEGER, time_window_minutes INTEGER, status VARCHAR, created_at DATETIME);
		CREATE TABLE incidents (id INTEGER PRIMARY KEY, title VARCHAR, description VARCHAR, severity VARCHAR, status VARCHAR, assigned_to VARCHAR, created_at DATETIME);
	`
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	if err := Up(db, SQLite); err != nil {
		t.Fatalf("adopt legacy schema: %v", err)
	}

	var version int
	var dirty bool
	if err := db.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("unexpected migration state: version=%d dirty=%v", version, dirty)
	}
}
