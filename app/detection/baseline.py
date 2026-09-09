import pandas as pd
import numpy as np
import json
import datetime
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from app.models.schema import EntityBaseline


def _upsert(db, table, values):
    """Build an INSERT ... ON CONFLICT DO UPDATE for the session's dialect.

    SQLite and Postgres both support the construct with the same API, but it
    lives in the dialect package, so the right one has to be chosen at runtime
    rather than imported once.
    """
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        return pg_insert(table).values(values)
    if dialect == 'sqlite':
        return sqlite_insert(table).values(values)
    raise RuntimeError(
        f"Unsupported database dialect '{dialect}'. "
        "Baseline upserts need SQLite or Postgres."
    )

def _compute_for_group(group_df):
    if group_df.empty:
        return 0.0, 0.0, "[]", "[]", 0
    
    sample_size = len(group_df)
    
    # We must make sure we resample on 'ts'
    resampled = group_df.set_index('ts').resample('1h').size()
    
    avg_events = resampled.mean() if not resampled.empty else 0.0
    std_events = resampled.std(ddof=1) if len(resampled) > 1 else 0.0
    
    if pd.isna(std_events):
        std_events = 0.0
        
    # Guardrail: sparse data gets a wide baseline band
    if sample_size < 5 or len(resampled) < 2:
        std_events = max(std_events, 20.0)
        
    logins = group_df[group_df['event'] == 'login']
    if not logins.empty:
        hours = logins['ts'].dt.hour
        top_hours = hours.value_counts().nlargest(3).index.tolist()
    else:
        top_hours = []
        
    resources = group_df[group_df['resource'].notna() & (group_df['resource'] != '')]['resource']
    if not resources.empty:
        top_res = resources.value_counts().nlargest(5).index.tolist()
    else:
        top_res = []
        
    return float(avg_events), float(std_events), json.dumps(top_hours), json.dumps(top_res), sample_size

def compute_baselines(db, df):
    if df.empty:
        return
        
    mappings = []
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for user, group in df.groupby('user'):
        if not user: continue
        avg_e, std_e, t_hours, t_res, sz = _compute_for_group(group)
        mappings.append({
            'entity_id': f"user:{user}",
            'avg_events_per_hour': avg_e,
            'std_events_per_hour': std_e,
            'typical_login_hours': t_hours,
            'typical_resources': t_res,
            'sample_size': sz,
            'updated_at': now_str
        })
        
    for ip, group in df.groupby('ip'):
        if not ip: continue
        avg_e, std_e, t_hours, t_res, sz = _compute_for_group(group)
        mappings.append({
            'entity_id': f"ip:{ip}",
            'avg_events_per_hour': avg_e,
            'std_events_per_hour': std_e,
            'typical_login_hours': t_hours,
            'typical_resources': t_res,
            'sample_size': sz,
            'updated_at': now_str
        })
        
    if mappings:
        stmt = _upsert(db, EntityBaseline, mappings)
        stmt = stmt.on_conflict_do_update(
            index_elements=['entity_id'],
            set_={
                'avg_events_per_hour': stmt.excluded.avg_events_per_hour,
                'std_events_per_hour': stmt.excluded.std_events_per_hour,
                'typical_login_hours': stmt.excluded.typical_login_hours,
                'typical_resources': stmt.excluded.typical_resources,
                'sample_size': stmt.excluded.sample_size,
                'updated_at': stmt.excluded.updated_at
            }
        )
        db.execute(stmt)
        db.commit()
