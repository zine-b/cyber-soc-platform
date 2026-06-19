package migrations

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratedatabase "github.com/golang-migrate/migrate/v4/database"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

type Dialect string

const (
	Postgres Dialect = "postgres"
	SQLite   Dialect = "sqlite"
)

//go:embed postgres/*.sql sqlite/*.sql
var files embed.FS

func Up(db *sql.DB, dialect Dialect) error {
	source, err := iofs.New(files, string(dialect))
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	var databaseDriverName string
	var databaseDriver migratedatabase.Driver
	switch dialect {
	case Postgres:
		databaseDriverName = "postgres"
		databaseDriver, err = migratepostgres.WithInstance(db, &migratepostgres.Config{})
	case SQLite:
		databaseDriverName = "sqlite3"
		databaseDriver, err = migratesqlite.WithInstance(db, &migratesqlite.Config{})
	default:
		return fmt.Errorf("unsupported migration dialect: %q", dialect)
	}
	if err != nil {
		return fmt.Errorf("initialize migration database driver: %w", err)
	}

	runner, err := migrate.NewWithInstance("iofs", source, databaseDriverName, databaseDriver)
	if err != nil {
		return fmt.Errorf("initialize migration runner: %w", err)
	}
	if err := runner.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
