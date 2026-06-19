package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyber-soc-platform/backend/internal/domain"
	"cyber-soc-platform/backend/internal/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrNotFound = errors.New("record not found")

type Store struct {
	db    *gorm.DB
	sqlDB *sql.DB
}

func Open(databaseURL string) (*Store, error) {
	driver, dsn, dialect, err := databaseConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	migrationDB, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := migrationDB.PingContext(ctx); err != nil {
		migrationDB.Close()
		return nil, err
	}
	if err := migrations.Up(migrationDB, dialect); err != nil {
		migrationDB.Close()
		return nil, fmt.Errorf("run database migrations: %w", err)
	}
	if err := migrationDB.Close(); err != nil {
		return nil, err
	}

	var dialector gorm.Dialector
	switch dialect {
	case migrations.Postgres:
		dialector = postgres.Open(dsn)
	case migrations.SQLite:
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database dialect: %q", dialect)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return &Store{db: db, sqlDB: sqlDB}, nil
}

func (s *Store) Close() error {
	return s.sqlDB.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.sqlDB.PingContext(ctx)
}

func databaseConfig(databaseURL string) (driver, dsn string, dialect migrations.Dialect, err error) {
	switch {
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return "pgx", databaseURL, migrations.Postgres, nil
	case strings.HasPrefix(databaseURL, "sqlite:///"):
		return "sqlite3", strings.TrimPrefix(databaseURL, "sqlite:///"), migrations.SQLite, nil
	case strings.HasPrefix(databaseURL, "sqlite://"):
		return "sqlite3", strings.TrimPrefix(databaseURL, "sqlite://"), migrations.SQLite, nil
	default:
		return "", "", "", fmt.Errorf("unsupported DATABASE_URL: %q", databaseURL)
	}
}

func (s *Store) CreateLog(ctx context.Context, logEntry domain.Log) (domain.Log, error) {
	err := s.db.WithContext(ctx).Create(&logEntry).Error
	return logEntry, err
}

func (s *Store) ListLogs(ctx context.Context, limit, offset int) ([]domain.Log, int, error) {
	var total int64
	if err := s.db.WithContext(ctx).Model(&domain.Log{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	logs := make([]domain.Log, 0)
	err := s.db.WithContext(ctx).Order("id DESC").Limit(limit).Offset(offset).Find(&logs).Error
	return logs, int(total), err
}

func (s *Store) DetectBruteForce(ctx context.Context, now time.Time) error {
	var recentLogs []domain.Log
	if err := s.db.WithContext(ctx).
		Where("received_at >= ?", now.Add(-10*time.Minute)).
		Find(&recentLogs).Error; err != nil {
		return err
	}

	counts := map[string]int{}
	for _, logEntry := range recentLogs {
		sourceIP, _ := logEntry.Parsed["source_ip"].(string)
		if logEntry.Parsed["category"] == "authentication" &&
			logEntry.Parsed["action"] == "login_failed" &&
			sourceIP != "" {
			counts[sourceIP]++
		}
	}

	for sourceIP, count := range counts {
		if count < 5 {
			continue
		}

		var existing domain.Alert
		err := s.db.WithContext(ctx).
			Where("source_ip = ? AND rule_id = ? AND status = ?", sourceIP, "SSH_BRUTE_FORCE", "open").
			First(&existing).Error
		if err == nil {
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		alert := domain.Alert{
			RuleID:            "SSH_BRUTE_FORCE",
			Title:             "Possible SSH brute force attack",
			Description:       fmt.Sprintf("%d failed SSH login attempts from %s in the last 10 minutes", count, sourceIP),
			Severity:          "high",
			SourceIP:          sourceIP,
			FailedAttempts:    count,
			TimeWindowMinutes: 10,
			Status:            "open",
			CreatedAt:         now,
		}
		if err := s.db.WithContext(ctx).Create(&alert).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListAlerts(ctx context.Context) ([]domain.Alert, error) {
	alerts := make([]domain.Alert, 0)
	err := s.db.WithContext(ctx).Order("id DESC").Find(&alerts).Error
	return alerts, err
}

func (s *Store) GetAlert(ctx context.Context, id int64) (domain.Alert, error) {
	var alert domain.Alert
	err := s.db.WithContext(ctx).First(&alert, id).Error
	return alert, mapError(err)
}

func (s *Store) UpdateAlertStatus(ctx context.Context, id int64, status string) (domain.Alert, error) {
	result := s.db.WithContext(ctx).Model(&domain.Alert{}).Where("id = ?", id).Update("status", status)
	if result.Error != nil {
		return domain.Alert{}, result.Error
	}
	if result.RowsAffected == 0 {
		return domain.Alert{}, ErrNotFound
	}
	return s.GetAlert(ctx, id)
}

func (s *Store) AssignAlert(ctx context.Context, alertID, incidentID int64) (domain.Alert, error) {
	if _, err := s.GetIncident(ctx, incidentID); err != nil {
		return domain.Alert{}, err
	}

	result := s.db.WithContext(ctx).
		Model(&domain.Alert{}).
		Where("id = ?", alertID).
		Update("incident_id", incidentID)
	if result.Error != nil {
		return domain.Alert{}, result.Error
	}
	if result.RowsAffected == 0 {
		return domain.Alert{}, ErrNotFound
	}
	return s.GetAlert(ctx, alertID)
}

func (s *Store) CreateIncident(ctx context.Context, incident domain.Incident) (domain.Incident, error) {
	err := s.db.WithContext(ctx).Create(&incident).Error
	return incident, err
}

func (s *Store) ListIncidents(ctx context.Context) ([]domain.Incident, error) {
	incidents := make([]domain.Incident, 0)
	err := s.db.WithContext(ctx).Order("id DESC").Find(&incidents).Error
	return incidents, err
}

func (s *Store) GetIncident(ctx context.Context, id int64) (domain.Incident, error) {
	var incident domain.Incident
	err := s.db.WithContext(ctx).First(&incident, id).Error
	return incident, mapError(err)
}

func (s *Store) AlertsByIncident(ctx context.Context, incidentID int64) ([]domain.Alert, error) {
	alerts := make([]domain.Alert, 0)
	err := s.db.WithContext(ctx).
		Where("incident_id = ?", incidentID).
		Order("id DESC").
		Find(&alerts).Error
	return alerts, err
}

func (s *Store) UpdateIncidentStatus(ctx context.Context, id int64, status string) (domain.Incident, error) {
	result := s.db.WithContext(ctx).Model(&domain.Incident{}).Where("id = ?", id).Update("status", status)
	if result.Error != nil {
		return domain.Incident{}, result.Error
	}
	if result.RowsAffected == 0 {
		return domain.Incident{}, ErrNotFound
	}
	return s.GetIncident(ctx, id)
}

func (s *Store) AssignIncident(ctx context.Context, id int64, assignedTo string) (domain.Incident, error) {
	result := s.db.WithContext(ctx).
		Model(&domain.Incident{}).
		Where("id = ?", id).
		Update("assigned_to", assignedTo)
	if result.Error != nil {
		return domain.Incident{}, result.Error
	}
	if result.RowsAffected == 0 {
		return domain.Incident{}, ErrNotFound
	}
	return s.GetIncident(ctx, id)
}

func mapError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
