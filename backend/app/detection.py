from datetime import datetime, timedelta
from app.models import LogModel, AlertModel


def detect_brute_force(db):
    """
    Détection :
    si une IP a 5 échecs SSH ou plus dans les 10 dernières minutes,
    créer une alerte.
    """

    now = datetime.utcnow()
    time_window_start = now - timedelta(minutes=10)

    recent_logs = (
        db.query(LogModel)
        .filter(LogModel.received_at >= time_window_start)
        .all()
    )

    failed_login_count_by_ip = {}

    for log in recent_logs:
        parsed = log.parsed or {}

        is_failed_login = (
            parsed.get("category") == "authentication"
            and parsed.get("action") == "login_failed"
            and parsed.get("source_ip") is not None
        )

        if is_failed_login:
            source_ip = parsed["source_ip"]
            failed_login_count_by_ip[source_ip] = failed_login_count_by_ip.get(source_ip, 0) + 1

    for source_ip, count in failed_login_count_by_ip.items():
        if count >= 5:
            alert_already_exists = (
                db.query(AlertModel)
                .filter(AlertModel.source_ip == source_ip)
                .filter(AlertModel.rule_id == "SSH_BRUTE_FORCE")
                .filter(AlertModel.status == "open")
                .first()
            )

            if not alert_already_exists:
                alert = AlertModel(
                    rule_id="SSH_BRUTE_FORCE",
                    title="Possible SSH brute force attack",
                    description=f"{count} failed SSH login attempts from {source_ip} in the last 10 minutes",
                    severity="high",
                    source_ip=source_ip,
                    failed_attempts=count,
                    time_window_minutes=10,
                    status="open",
                    incident_id=None,
                    created_at=datetime.utcnow()
                )

                db.add(alert)
                db.commit()