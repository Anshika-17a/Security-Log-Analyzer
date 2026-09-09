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
    
    incidents = []
    
    for (user, time_window), group in df.groupby(['user', pd.Grouper(key='timestamp', freq='30min')]):
        alert_ids = group['id'].tolist()
        group_alerts = [a for a in all_alerts if a.id in alert_ids]
        
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
            updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        db.add(incident)
        db.flush()
        
        for a in group_alerts:
            a.incident_id = incident.id
            
        actions = generate_recommendations(incident.id, group_alerts)
        for action in actions:
            db.add(action)
            
        incidents.append(incident)
        
    db.commit()
    return incidents
