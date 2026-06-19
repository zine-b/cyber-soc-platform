package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyber-soc-platform/backend/internal/api"
	"cyber-soc-platform/backend/internal/config"
	"cyber-soc-platform/backend/internal/store"
)

func TestBruteForceWorkflow(t *testing.T) {
	databaseURL := "sqlite:///" + filepath.Join(t.TempDir(), "soc.db")
	db, err := store.Open(databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()

	handler := api.New(db, config.Config{FrontendURL: "http://localhost:5173"})

	for index, username := range []string{"root", "admin", "test", "ubuntu", "postgres"} {
		body, _ := json.Marshal(map[string]string{
			"source":   "linux-server-01",
			"log_type": "linux_auth",
			"message":  fmt.Sprintf("Failed password for %s from 185.10.20.30 port %d ssh2", username, 52344+index),
		})
		request := httptest.NewRequest(http.MethodPost, "/ingest/log", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("ingest %d returned %d: %s", index+1, response.Code, response.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("list alerts returned %d: %s", response.Code, response.Body.String())
	}

	var payload struct {
		Count  int `json:"count"`
		Alerts []struct {
			RuleID   string `json:"rule_id"`
			SourceIP string `json:"source_ip"`
			Status   string `json:"status"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode alerts response: %v", err)
	}
	if payload.Count != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("expected one alert, got %#v", payload)
	}
	alert := payload.Alerts[0]
	if alert.RuleID != "SSH_BRUTE_FORCE" || alert.SourceIP != "185.10.20.30" || alert.Status != "open" {
		t.Fatalf("unexpected alert: %#v", alert)
	}
}
