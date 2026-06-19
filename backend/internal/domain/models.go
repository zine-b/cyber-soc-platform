package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

type JSONMap map[string]any

func (value JSONMap) Value() (driver.Value, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}

func (value *JSONMap) Scan(source any) error {
	if source == nil {
		*value = nil
		return nil
	}

	var raw []byte
	switch typed := source.(type) {
	case []byte:
		raw = typed
	case string:
		raw = []byte(typed)
	default:
		return fmt.Errorf("unsupported JSON database value %T", source)
	}
	return json.Unmarshal(raw, value)
}

type Log struct {
	ID         int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	Source     string    `json:"source"`
	LogType    string    `json:"log_type"`
	Message    string    `json:"message"`
	Parsed     JSONMap   `json:"parsed" gorm:"type:json"`
	ReceivedAt time.Time `json:"received_at" gorm:"autoCreateTime:false"`
}

type Alert struct {
	ID                int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	RuleID            string    `json:"rule_id"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	Severity          string    `json:"severity"`
	SourceIP          string    `json:"source_ip"`
	FailedAttempts    int       `json:"failed_attempts"`
	TimeWindowMinutes int       `json:"time_window_minutes"`
	Status            string    `json:"status"`
	IncidentID        *int64    `json:"incident_id"`
	CreatedAt         time.Time `json:"created_at" gorm:"autoCreateTime:false"`
}

type Incident struct {
	ID          int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	AssignedTo  *string   `json:"assigned_to"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime:false"`
}
