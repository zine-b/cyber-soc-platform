import { useEffect, useState } from "react";
import apiClient from "./api/client";
import "./index.css";

function App() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);

  async function fetchData() {
    try {
      setLoading(true);

      const logsResponse = await apiClient.get("/logs");
      const alertsResponse = await apiClient.get("/alerts");
      const incidentsResponse = await apiClient.get("/incidents");

      setLogs(logsResponse.data.logs || []);
      setAlerts(alertsResponse.data.alerts || []);
      setIncidents(incidentsResponse.data.incidents || []);
    } catch (error) {
      console.error("Error fetching data:", error);
      alert("Erreur lors du chargement des données depuis le backend.");
    } finally {
      setLoading(false);
    }
  }

  async function sendTestLogs() {
    const testLogs = [
      {
        source: "linux-server-01",
        log_type: "linux_auth",
        message: "Failed password for root from 185.10.20.30 port 52344 ssh2",
      },
      {
        source: "linux-server-01",
        log_type: "linux_auth",
        message: "Failed password for admin from 185.10.20.30 port 52345 ssh2",
      },
      {
        source: "linux-server-01",
        log_type: "linux_auth",
        message: "Failed password for test from 185.10.20.30 port 52346 ssh2",
      },
      {
        source: "linux-server-01",
        log_type: "linux_auth",
        message: "Failed password for ubuntu from 185.10.20.30 port 52347 ssh2",
      },
      {
        source: "linux-server-01",
        log_type: "linux_auth",
        message: "Failed password for postgres from 185.10.20.30 port 52348 ssh2",
      },
    ];

    try {
      setLoading(true);

      for (const log of testLogs) {
        await apiClient.post("/ingest/log", log);
      }

      await fetchData();
      alert("Logs de test envoyés avec succès.");
    } catch (error) {
      console.error("Error sending test logs:", error);
      alert("Erreur lors de l'envoi des logs de test.");
    } finally {
      setLoading(false);
    }
  }

  async function createIncident() {
    try {
      setLoading(true);

      await apiClient.post("/incidents", {
        title: "Possible SSH brute force on linux-server-01",
        description:
          "Multiple failed SSH login attempts detected from IP 185.10.20.30 against linux-server-01.",
        severity: "high",
      });

      await fetchData();
      alert("Incident créé avec succès.");
    } catch (error) {
      console.error("Error creating incident:", error);
      alert("Erreur lors de la création de l'incident.");
    } finally {
      setLoading(false);
    }
  }

  async function assignIncident(incidentId) {
    try {
      setLoading(true);

      await apiClient.patch(`/incidents/${incidentId}/assign`, {
        assigned_to: "zineb",
      });

      await fetchData();
      alert("Incident assigné à zineb.");
    } catch (error) {
      console.error("Error assigning incident:", error);
      alert("Erreur lors de l'assignation de l'incident.");
    } finally {
      setLoading(false);
    }
  }

  async function updateIncidentStatus(incidentId, status) {
    try {
      setLoading(true);

      await apiClient.patch(`/incidents/${incidentId}/status`, {
        status,
      });

      await fetchData();
    } catch (error) {
      console.error("Error updating incident status:", error);
      alert("Erreur lors du changement de statut.");
    } finally {
      setLoading(false);
    }
  }

  async function assignAlertToIncident(alertId, incidentId) {
    try {
      setLoading(true);

      await apiClient.patch(`/alerts/${alertId}/assign-incident`, {
        incident_id: incidentId,
      });

      await fetchData();
      alert("Alerte liée à l'incident.");
    } catch (error) {
      console.error("Error assigning alert:", error);
      alert("Erreur lors de la liaison alerte/incident.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData();
  }, []);

  const openAlerts = alerts.filter((alert) => alert.status === "open");
  const highAlerts = alerts.filter((alert) => alert.severity === "high");
  const openIncidents = incidents.filter((incident) => incident.status === "open");

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>Cyber SOC</h2>
        <nav>
          <a href="#dashboard">Dashboard</a>
          <a href="#logs">Logs</a>
          <a href="#alerts">Alertes</a>
          <a href="#incidents">Incidents</a>
        </nav>
      </aside>

      <main className="main">
        <header className="header">
          <div>
            <h1>Mini SOC Dashboard</h1>
            <p>Surveillance des logs, alertes et incidents.</p>
          </div>

          <div className="actions">
            <button onClick={fetchData} disabled={loading}>
              Rafraîchir
            </button>
            <button onClick={sendTestLogs} disabled={loading}>
              Envoyer logs test
            </button>
            <button onClick={createIncident} disabled={loading}>
              Créer incident
            </button>
          </div>
        </header>

        <section id="dashboard" className="cards">
          <div className="card">
            <span>Total logs</span>
            <strong>{logs.length}</strong>
          </div>

          <div className="card">
            <span>Total alertes</span>
            <strong>{alerts.length}</strong>
          </div>

          <div className="card danger">
            <span>Alertes ouvertes</span>
            <strong>{openAlerts.length}</strong>
          </div>

          <div className="card warning">
            <span>Alertes high</span>
            <strong>{highAlerts.length}</strong>
          </div>

          <div className="card">
            <span>Incidents</span>
            <strong>{incidents.length}</strong>
          </div>

          <div className="card warning">
            <span>Incidents ouverts</span>
            <strong>{openIncidents.length}</strong>
          </div>
        </section>

        <section id="alerts" className="panel">
          <h2>Alertes</h2>

          {alerts.length === 0 ? (
            <p>Aucune alerte pour le moment.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Titre</th>
                  <th>Sévérité</th>
                  <th>IP source</th>
                  <th>Statut</th>
                  <th>Incident</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.id}</td>
                    <td>{alert.title}</td>
                    <td>
                      <span className={`badge ${alert.severity}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>{alert.source_ip}</td>
                    <td>{alert.status}</td>
                    <td>{alert.incident_id || "Non lié"}</td>
                    <td>
                      {incidents.length > 0 && !alert.incident_id && (
                        <button
                          onClick={() =>
                            assignAlertToIncident(alert.id, incidents[0].id)
                          }
                        >
                          Lier à incident #{incidents[0].id}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section id="incidents" className="panel">
          <h2>Incidents</h2>

          {incidents.length === 0 ? (
            <p>Aucun incident pour le moment.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Titre</th>
                  <th>Sévérité</th>
                  <th>Statut</th>
                  <th>Assigné à</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>{incident.id}</td>
                    <td>{incident.title}</td>
                    <td>
                      <span className={`badge ${incident.severity}`}>
                        {incident.severity}
                      </span>
                    </td>
                    <td>{incident.status}</td>
                    <td>{incident.assigned_to || "Non assigné"}</td>
                    <td className="table-actions">
                      {!incident.assigned_to && (
                        <button onClick={() => assignIncident(incident.id)}>
                          Assigner
                        </button>
                      )}

                      <button
                        onClick={() =>
                          updateIncidentStatus(incident.id, "investigating")
                        }
                      >
                        Investigating
                      </button>

                      <button
                        onClick={() =>
                          updateIncidentStatus(incident.id, "resolved")
                        }
                      >
                        Resolved
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section id="logs" className="panel">
          <h2>Logs récents</h2>

          {logs.length === 0 ? (
            <p>Aucun log pour le moment.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Action</th>
                  <th>Username</th>
                  <th>IP source</th>
                  <th>Message</th>
                </tr>
              </thead>

              <tbody>
                {logs.slice(0, 20).map((log) => (
                  <tr key={log.id}>
                    <td>{log.id}</td>
                    <td>{log.source}</td>
                    <td>{log.log_type}</td>
                    <td>{log.parsed?.action || "-"}</td>
                    <td>{log.parsed?.username || "-"}</td>
                    <td>{log.parsed?.source_ip || "-"}</td>
                    <td className="message">{log.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;