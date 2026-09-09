import pandas as pd
import datetime
from sqlalchemy.orm import Session
from app.models.schema import Alert, Incident, IncidentAction
from app.correlation.scoring import calculate_score
from app.remediation.recommendations import generate_recommendations

def group_and_correlate(db: Session):
    # Idempotency: clear existing incidents and remove assignment from alerts.
    # IncidentAction rows must go too - a bulk delete bypasses the ORM cascade
    # (and SQLite does not enforce ON DELETE CASCADE unless PRAGMA foreign_keys
    # is on), so without this every call appends a duplicate set of actions.
    db.query(Alert).update({Alert.incident_id: None})
    db.query(IncidentAction).delete()
    db.query(Incident).delete()
    db.commit()

    all_alerts = db.query(Alert).all()
    if not all_alerts:
        return []
        
    df = pd.DataFrame([a.__dict__ for a in all_alerts])
    if '_sa_instance_state' in df.columns:
        df = df.drop(columns=['_sa_instance_state'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', errors='coerce')
    df = df.dropna(subset=['timestamp'])
    
    # id -> Alert, so building each group is O(size of group) rather than a
    # full scan of every alert per group (which was O(alerts x groups)).
    alerts_by_id = {a.id: a for a in all_alerts}

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    pending = []

    for (user, time_window), group in df.groupby(['user', pd.Grouper(key='timestamp', freq='30min')]):
        group_alerts = [alerts_by_id[i] for i in group['id'].tolist() if i in alerts_by_id]
        if not group_alerts:
            continue

        score, risk_level = calculate_score(group_alerts)
        rule_names = list(set([a.rule_name for a in group_alerts]))

        ip_list = group['ip'].dropna().unique().tolist()
        ip_str = ip_list[0] if ip_list else ""

        incident = Incident(
            user=user,
            ip=ip_str,
            risk_level=risk_level,
            score=score,
            alert_count=len(group_alerts),
            rules=",".join(rule_names),
            first_event_time=group['timestamp'].min().isoformat(),
            last_event_time=group['timestamp'].max().isoformat(),
            status="open",
            updated_at=now
        )
        db.add(incident)
        pending.append((incident, group_alerts))

    if not pending:
        db.commit()
        return []

    # One flush populates every incident's primary key. Flushing inside the
    # loop cost a network round trip per incident, which dominates runtime on
    # a hosted database even though it is nearly free on local SQLite.
    db.flush()

    alert_updates = []
    for incident, group_alerts in pending:
        for a in group_alerts:
            alert_updates.append({"id": a.id, "incident_id": incident.id})
        for action in generate_recommendations(incident.id, group_alerts):
            db.add(action)

    # Send the alert->incident links as a single batched statement instead of
    # one UPDATE per alert.
    if alert_updates:
        db.bulk_update_mappings(Alert, alert_updates)

    db.commit()
    return [inc for inc, _ in pending]
