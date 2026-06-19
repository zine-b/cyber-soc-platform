package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyber-soc-platform/backend/internal/config"
	"cyber-soc-platform/backend/internal/domain"
	"cyber-soc-platform/backend/internal/security"
	"cyber-soc-platform/backend/internal/store"
)

type API struct {
	store  *store.Store
	config config.Config
}

func New(store *store.Store, cfg config.Config) http.Handler {
	api := &API{store: store, config: cfg}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", api.home)
	mux.HandleFunc("GET /health", api.health)
	mux.HandleFunc("POST /ingest/log", api.ingestLog)
	mux.HandleFunc("GET /logs", api.listLogs)
	mux.HandleFunc("GET /alerts", api.listAlerts)
	mux.HandleFunc("GET /alerts/{id}", api.getAlert)
	mux.HandleFunc("PATCH /alerts/{id}/status", api.updateAlertStatus)
	mux.HandleFunc("PATCH /alerts/{id}/assign-incident", api.assignAlert)
	mux.HandleFunc("POST /incidents", api.createIncident)
	mux.HandleFunc("GET /incidents", api.listIncidents)
	mux.HandleFunc("GET /incidents/{id}", api.getIncident)
	mux.HandleFunc("PATCH /incidents/{id}/status", api.updateIncidentStatus)
	mux.HandleFunc("PATCH /incidents/{id}/assign", api.assignIncident)
	mux.HandleFunc("GET /openapi.json", api.openapi)
	mux.HandleFunc("GET /docs", api.docs)

	return api.recover(api.cors(api.logging(mux)))
}

func (a *API) home(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"message": "Cyber SOC Platform API is running"})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy", "service": "backend"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "healthy", "service": "backend"})
}

func (a *API) ingestLog(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Source  string `json:"source"`
		LogType string `json:"log_type"`
		Message string `json:"message"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Source == "" || input.LogType == "" || input.Message == "" {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse("source, log_type and message are required"))
		return
	}

	parsed := map[string]any{}
	if input.LogType == "linux_auth" {
		parsed = security.ParseLinuxAuthLog(input.Message)
	}
	now := time.Now().UTC()
	logEntry, err := a.store.CreateLog(r.Context(), domain.Log{
		Source: input.Source, LogType: input.LogType, Message: input.Message, Parsed: domain.JSONMap(parsed), ReceivedAt: now,
	})
	if err != nil {
		internalError(w, err)
		return
	}
	if err := a.store.DetectBruteForce(r.Context(), now); err != nil {
		internalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Log received, parsed, analyzed and saved successfully",
		"data":    logEntry,
	})
}

func (a *API) listLogs(w http.ResponseWriter, r *http.Request) {
	page := positiveInt(r.URL.Query().Get("page"), 1)
	limit := positiveInt(r.URL.Query().Get("limit"), 10)
	if limit > 100 {
		limit = 100
	}

	logs, total, err := a.store.ListLogs(r.Context(), limit, (page-1)*limit)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(logs), "total": total, "page": page, "limit": limit,
		"total_pages": (total + limit - 1) / limit, "logs": logs,
	})
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := a.store.ListAlerts(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(alerts), "alerts": alerts})
}

func (a *API) getAlert(w http.ResponseWriter, r *http.Request) {
	alert, err := a.store.GetAlert(r.Context(), pathID(r))
	if handleNotFound(w, err, "Alert not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "alert": alert})
}

func (a *API) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !oneOf(input.Status, "open", "investigating", "resolved", "false_positive") {
		writeJSON(w, http.StatusOK, errorResponse("Invalid status. Allowed values: [open investigating resolved false_positive]"))
		return
	}
	alert, err := a.store.UpdateAlertStatus(r.Context(), pathID(r), input.Status)
	if handleNotFound(w, err, "Alert not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Alert status updated successfully", "alert": alert,
	})
}

func (a *API) assignAlert(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IncidentID int64 `json:"incident_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if _, err := a.store.GetAlert(r.Context(), pathID(r)); err != nil {
		if handleNotFound(w, err, "Alert not found") {
			return
		}
		internalError(w, err)
		return
	}
	alert, err := a.store.AssignAlert(r.Context(), pathID(r), input.IncidentID)
	if handleNotFound(w, err, "Incident not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Alert assigned to incident successfully", "alert": alert,
	})
}

func (a *API) createIncident(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Title == "" || input.Description == "" || input.Severity == "" {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse("title, description and severity are required"))
		return
	}
	if !oneOf(input.Severity, "low", "medium", "high", "critical") {
		writeJSON(w, http.StatusOK, errorResponse("Invalid severity. Allowed values: [low medium high critical]"))
		return
	}
	incident, err := a.store.CreateIncident(r.Context(), domain.Incident{
		Title: input.Title, Description: input.Description, Severity: input.Severity, Status: "open", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Incident created successfully", "incident": incident,
	})
}

func (a *API) listIncidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := a.store.ListIncidents(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(incidents), "incidents": incidents})
}

func (a *API) getIncident(w http.ResponseWriter, r *http.Request) {
	incident, err := a.store.GetIncident(r.Context(), pathID(r))
	if handleNotFound(w, err, "Incident not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	alerts, err := a.store.AlertsByIncident(r.Context(), incident.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "incident": incident, "linked_alerts_count": len(alerts), "linked_alerts": alerts,
	})
}

func (a *API) updateIncidentStatus(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !oneOf(input.Status, "open", "investigating", "resolved", "false_positive") {
		writeJSON(w, http.StatusOK, errorResponse("Invalid status. Allowed values: [open investigating resolved false_positive]"))
		return
	}
	incident, err := a.store.UpdateIncidentStatus(r.Context(), pathID(r), input.Status)
	if handleNotFound(w, err, "Incident not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Incident status updated successfully", "incident": incident,
	})
}

func (a *API) assignIncident(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AssignedTo string `json:"assigned_to"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	incident, err := a.store.AssignIncident(r.Context(), pathID(r), input.AssignedTo)
	if handleNotFound(w, err, "Incident not found") {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Incident assigned successfully", "incident": incident,
	})
}

func (a *API) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(openAPISpec))
}

func (a *API) docs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, swaggerHTML)
}

func (a *API) cors(next http.Handler) http.Handler {
	allowed := map[string]bool{
		a.config.FrontendURL:    true,
		"http://127.0.0.1:5173": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(started).Round(time.Millisecond))
	})
}

func (a *API) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("panic: %v", recovered)
				writeJSON(w, http.StatusInternalServerError, errorResponse("Internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse("Invalid JSON body"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeJSON(w, http.StatusInternalServerError, errorResponse("Internal server error"))
}

func handleNotFound(w http.ResponseWriter, err error, message string) bool {
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, errorResponse(message))
		return true
	}
	return false
}

func errorResponse(message string) map[string]any {
	return map[string]any{"status": "error", "message": message}
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func positiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

var swaggerHTML = `<!doctype html>
<html><head><title>Cyber SOC Platform API - Swagger UI</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/openapi.json",dom_id:"#swagger-ui"});</script></body></html>`

var openAPISpec = strings.TrimSpace(`{
  "openapi": "3.1.0",
  "info": {"title": "Cyber SOC Platform API", "version": "0.1.0", "description": "Mini plateforme SOC pour collecter et analyser des logs"},
  "paths": {
    "/": {"get": {"summary": "API status", "responses": {"200": {"description": "OK"}}}},
    "/health": {"get": {"summary": "Health check", "responses": {"200": {"description": "Healthy"}}}},
    "/ingest/log": {"post": {"summary": "Ingest and analyze a log", "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LogInput"}}}}, "responses": {"200": {"description": "Log ingested"}}}},
    "/logs": {"get": {"summary": "List logs", "parameters": [{"name":"page","in":"query","schema":{"type":"integer","default":1}},{"name":"limit","in":"query","schema":{"type":"integer","default":10,"maximum":100}}], "responses": {"200": {"description": "Paginated logs"}}}},
    "/alerts": {"get": {"summary": "List alerts", "responses": {"200": {"description": "Alerts"}}}},
    "/alerts/{id}": {"get": {"summary": "Get alert", "parameters": [{"$ref":"#/components/parameters/ID"}], "responses": {"200": {"description": "Alert"}}}},
    "/alerts/{id}/status": {"patch": {"summary": "Update alert status", "parameters": [{"$ref":"#/components/parameters/ID"}], "requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/StatusUpdate"}}}}, "responses":{"200":{"description":"Updated alert"}}}},
    "/alerts/{id}/assign-incident": {"patch": {"summary": "Assign alert to incident", "parameters": [{"$ref":"#/components/parameters/ID"}], "requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["incident_id"],"properties":{"incident_id":{"type":"integer"}}}}}}, "responses":{"200":{"description":"Assigned alert"}}}},
    "/incidents": {
      "get": {"summary": "List incidents", "responses": {"200": {"description": "Incidents"}}},
      "post": {"summary": "Create incident", "requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/IncidentCreate"}}}}, "responses":{"200":{"description":"Created incident"}}}
    },
    "/incidents/{id}": {"get": {"summary": "Get incident and linked alerts", "parameters": [{"$ref":"#/components/parameters/ID"}], "responses": {"200": {"description": "Incident"}}}},
    "/incidents/{id}/status": {"patch": {"summary": "Update incident status", "parameters": [{"$ref":"#/components/parameters/ID"}], "requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/StatusUpdate"}}}}, "responses":{"200":{"description":"Updated incident"}}}},
    "/incidents/{id}/assign": {"patch": {"summary": "Assign incident", "parameters": [{"$ref":"#/components/parameters/ID"}], "requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["assigned_to"],"properties":{"assigned_to":{"type":"string"}}}}}}, "responses":{"200":{"description":"Assigned incident"}}}}
  },
  "components": {
    "parameters": {"ID":{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}},
    "schemas": {
      "LogInput":{"type":"object","required":["source","log_type","message"],"properties":{"source":{"type":"string"},"log_type":{"type":"string"},"message":{"type":"string"}}},
      "StatusUpdate":{"type":"object","required":["status"],"properties":{"status":{"type":"string","enum":["open","investigating","resolved","false_positive"]}}},
      "IncidentCreate":{"type":"object","required":["title","description","severity"],"properties":{"title":{"type":"string"},"description":{"type":"string"},"severity":{"type":"string","enum":["low","medium","high","critical"]}}}
    }
  }
}`)
