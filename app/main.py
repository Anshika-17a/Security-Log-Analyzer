import os
import hashlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import pandas as pd

from app.models.db import init_db, get_db
from app.models.schema import Log, Alert, Incident, IncidentAction, AuditLog
from app.models.api import (
    UploadResponse, HealthResponse, AlertsResponse, 
    IncidentListResponse, IncidentDetailResponse, 
    StatusUpdateRequest, NarrativeResponse
)
from app.ingestion.parser import parse_and_ingest_csv
from app.detection.rules import run_all_rules
from app.detection.baseline import compute_baselines
from app.detection.ml_anomaly import detect_anomalies
from app.correlation.grouping import group_and_correlate
from app.reporting.report_generator import generate_incident_report_md, generate_summary_report_md, convert_markdown_to_pdf
from app.reporting.narrative import cluster_logs, generate_llm_narrative


SEED_FILE = os.environ.get("SEED_FILE", "data/sample_logs.csv")


def _seed_demo_data():
    """Populate an empty database with the bundled sample logs and run the
    full detection + correlation pipeline.

    Hosted free tiers use an ephemeral filesystem, so the SQLite file is wiped
    on every redeploy/restart. Without this the deployed dashboard would come
    up empty. No-ops if logs already exist or the seed file is missing.
    """
    from app.models.db import SessionLocal

    if not os.path.exists(SEED_FILE):
        print(f"[seed] skipped: {SEED_FILE} not found")
        return

    db = SessionLocal()
    try:
        if db.query(Log).count() > 0:
            print("[seed] skipped: database already has logs")
            return

        print(f"[seed] ingesting {SEED_FILE} ...")
        with open(SEED_FILE, "rb") as fh:
            result = parse_and_ingest_csv(fh, db, filename=os.path.basename(SEED_FILE))
        if result.get("status") == "error":
            print(f"[seed] ingest failed: {result.get('message')}")
            return

        alerts = _generate_alerts(db)
        incidents = group_and_correlate(db)
        print(f"[seed] done: {result.get('rows_inserted', 0)} logs, "
              f"{len(alerts)} alerts, {len(incidents)} incidents")
    except Exception as exc:  # never let seeding block startup
        db.rollback()
        print(f"[seed] error: {type(exc).__name__}: {exc}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if os.environ.get("SEED_ON_START", "false").lower() in ("1", "true", "yes"):
        _seed_demo_data()
    yield

app = FastAPI(
    title="Security Log Analyzer",
    description="A hybrid rule-based and ML-based security log analysis and correlation engine.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def to_dict(obj):
    d = obj.__dict__.copy()
    d.pop('_sa_instance_state', None)
    return d

templates = Jinja2Templates(directory="app/dashboard/templates")

@app.get("/", response_class=HTMLResponse, summary="Dashboard UI", include_in_schema=False)
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    total = db.query(Incident).count()
    critical = db.query(Incident).filter(Incident.risk_level == "Critical").count()
    high = db.query(Incident).filter(Incident.risk_level == "High").count()
    medium = db.query(Incident).filter(Incident.risk_level == "Medium").count()
    low = db.query(Incident).filter(Incident.risk_level == "Low").count()
    
    top_incidents = db.query(Incident).order_by(Incident.score.desc()).limit(20).all()
    
    counts = {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
    
    return templates.TemplateResponse(request, "dashboard.html", {
        "counts": counts,
        "top_incidents": top_incidents,
        "last_refreshed": pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S UTC")
    })

@app.get("/health", response_model=HealthResponse, summary="Health Check")
def health_check():
    return {"status": "ok"}

@app.post("/api/logs/upload", response_model=UploadResponse, summary="Upload Logs", description="Uploads a CSV, JSON, JSONL or syslog file for ingestion.")
def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    filename = file.filename or "upload.csv"
    
    import io
    result = parse_and_ingest_csv(io.BytesIO(content), db, filename=filename)
    
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message", "Parse error"))
    
    processed = result.get("rows_inserted", 0)
    skipped   = result.get("rows_skipped", 0)
    fmt       = result.get("format", "csv")
    
    return {"status": "success", "processed": processed, "skipped": skipped}


def _generate_alerts(db: Session) -> list:
    """Run baselines + rule engine + ML detector over all ingested logs.

    Shared by the /api/alerts endpoint and the startup demo seeder.
    """
    logs = db.query(Log).all()
    if not logs:
        return []

    df = pd.DataFrame([l.__dict__ for l in logs])
    if '_sa_instance_state' in df.columns:
        df = df.drop(columns=['_sa_instance_state'])
    df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
    df = df.dropna(subset=['ts']).copy()

    compute_baselines(db, df)
    raw_alerts = run_all_rules(df)

    alert_mappings = []
    for alert_dict, evidence in raw_alerts:
        ad = alert_dict.copy()
        ad['evidence'] = evidence
        alert_mappings.append(ad)

    ml_alerts = detect_anomalies(db, df, alert_mappings)
    all_alerts = alert_mappings + ml_alerts

    if all_alerts:
        db.bulk_insert_mappings(Alert, all_alerts)
        db.commit()

    return all_alerts


@app.get("/api/alerts", response_model=AlertsResponse, summary="Generate Alerts", description="Runs the rule engine and ML baseline anomaly detection to generate alerts from the ingested logs.")
def get_alerts(db: Session = Depends(get_db)):
    all_alerts = _generate_alerts(db)
    return {"status": "success", "alerts_generated": len(all_alerts), "alerts": all_alerts}

@app.get("/api/incidents", response_model=IncidentListResponse, summary="Correlate Incidents", description="Groups unassigned alerts into candidate incidents, calculates dynamic risk scores, and generates remediation recommendations.")
def get_incidents(db: Session = Depends(get_db)):
    incidents = group_and_correlate(db)
    incidents_sorted = sorted(incidents, key=lambda x: x.score, reverse=True)
    return {"status": "success", "total_incidents": len(incidents_sorted), "incidents": [to_dict(i) for i in incidents_sorted]}

@app.get("/api/incidents/{id}", response_model=IncidentDetailResponse, summary="Get Incident Details", description="Retrieves the detailed view of a specific incident, including evidence strings, fired rules, and recommended actions.")
def get_incident_detail(id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    alerts = db.query(Alert).filter(Alert.incident_id == id).all()
    actions = db.query(IncidentAction).filter(IncidentAction.incident_id == id).all()
    
    evidence_strings = [a.evidence for a in alerts]
    rules_fired = list(set([a.rule_name for a in alerts]))
    ml_anomaly_score = max([a.ml_anomaly_score for a in alerts if a.ml_anomaly_score is not None] or [None])
    contributing_alert_ids = [a.id for a in alerts]
    
    return {
        "status": "success",
        "incident": to_dict(incident),
        "evidence_strings": evidence_strings,
        "rules_fired": rules_fired,
        "ml_anomaly_score": ml_anomaly_score,
        "contributing_alert_ids": contributing_alert_ids,
        "recommended_actions": [to_dict(act) for act in actions]
    }

@app.put("/api/incidents/{id}/status", summary="Update Incident Status", description="Atomically updates the status of an incident and records an AuditLog entry.")
def update_incident_status(id: int, request: StatusUpdateRequest, db: Session = Depends(get_db)):
    if request.status not in ("open", "reviewing", "resolved", "false_positive"):
        raise HTTPException(status_code=422, detail="Invalid status")
        
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    old_status = incident.status
    
    try:
        incident.status = request.status
        incident.updated_at = pd.Timestamp.now(tz="UTC").isoformat()
        
        audit_log = AuditLog(
            incident_id=id,
            change_type="status_update",
            old_value=old_status,
            new_value=request.status,
            changed_by=getattr(request, "changed_by", "system")
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database transaction failed")
        
    return {"status": "success", "message": "Incident status updated successfully"}

@app.get("/api/reports/summary", summary="Org-wide Summary Report", description="Generates an organization-wide summary report across all open incidents.")
def get_summary_report(format: str = "pdf", db: Session = Depends(get_db)):
    incidents = db.query(Incident).filter(Incident.status == "open").all()
    md = generate_summary_report_md(incidents)
    if format == "md":
        return PlainTextResponse(md)
    pdf_bytes = convert_markdown_to_pdf(None, summary_incidents=incidents)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="security_summary_report.pdf"'})

@app.get("/api/reports/{id}", summary="Incident Report", description="Generates a human-readable report for a specific incident.")
def get_incident_report(id: int, format: str = "pdf", db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    alerts = db.query(Alert).filter(Alert.incident_id == id).all()
    actions = db.query(IncidentAction).filter(IncidentAction.incident_id == id).all()
    
    md = generate_incident_report_md(incident, alerts, actions)
    if format == "md":
        return PlainTextResponse(md)
    pdf_bytes = convert_markdown_to_pdf(None, incident=incident, alerts=alerts, actions=actions)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="incident_{id}_report.pdf"'})

@app.get("/api/incidents/{id}/narrative", response_model=NarrativeResponse, summary="Generate LLM Narrative", description="Clusters incident logs via Drain3 and prompts an LLM for an executive summary.")
def get_incident_narrative(id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    logs = db.query(Log).filter(
        Log.user == incident.user,
        Log.ts >= incident.first_event_time,
        Log.ts <= incident.last_event_time
    ).all()
    
    raw_lines = [l.raw_line for l in logs if l.raw_line]
    
    clustered = cluster_logs(raw_lines)
    
    context = {
        "user": incident.user,
        "risk_level": incident.risk_level,
        "score": incident.score,
        "rules": incident.rules
    }
    
    narrative = generate_llm_narrative(context, clustered)
    
    return {
        "status": "success",
        "incident_id": id,
        "narrative": narrative
    }
