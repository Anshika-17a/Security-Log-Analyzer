"""
ML Anomaly Detection — per-user IsolationForest with persisted baselines.

How it works:
1. For every (user, 1-hour-window) in the logs we extract 9 behavioural features.
2. We train ONE IsolationForest per user on ALL their historical windows.
3. Score = how anomalous is THIS window relative to THAT user's own history.
4. Because each model is fitted on that user's own data, a user who always logs
   in at 3 AM won't be flagged for it; a user who normally works 9-5 WILL be.
5. Raw IsolationForest scores are normalised 0–1 per user so they're comparable.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.models.schema import EntityBaseline

# ── Features extracted per (user, 1-hour-window) ────────────────────────────
FEATURE_COLS = [
    "failed_login_count",
    "distinct_ips_used",
    "distinct_resources_touched",
    "off_hours_event_ratio",
    "blocked_event_ratio",
    "avg_time_between_events",
    "privilege_change_count",
    "export_volume",
    "event_count",
]

# Flag a window as anomalous if its score exceeds this threshold
ANOMALY_THRESHOLD = 0.60


def _extract_features(group: pd.DataFrame) -> dict:
    """Compute the 9 behavioural features for one (user, hour-window) group."""
    count = len(group)
    status = group["status"].fillna("").str.lower()
    event  = group["event"].fillna("").str.lower()
    hours  = group["ts"].dt.hour

    failed_login_count         = int(((status == "failed") & event.str.contains("login", na=False)).sum())
    distinct_ips_used          = int(group["ip"].nunique())
    distinct_resources_touched = int(group["resource"].nunique())
    off_hours_event_ratio      = float(((hours >= 22) | (hours < 6)).sum() / count)
    blocked_event_ratio        = float((status == "blocked").sum() / count)
    privilege_change_count     = int(event.isin(["privilege_escalation", "role_elevation"]).sum())
    export_volume              = int((event == "export").sum())

    if count > 1:
        delta = (group["ts"].max() - group["ts"].min()).total_seconds()
        avg_time_between_events = float(delta / (count - 1))
    else:
        avg_time_between_events = 0.0

    return {
        "failed_login_count":          failed_login_count,
        "distinct_ips_used":           distinct_ips_used,
        "distinct_resources_touched":  distinct_resources_touched,
        "off_hours_event_ratio":       off_hours_event_ratio,
        "blocked_event_ratio":         blocked_event_ratio,
        "avg_time_between_events":     avg_time_between_events,
        "privilege_change_count":      privilege_change_count,
        "export_volume":               export_volume,
        "event_count":                 count,
    }


def _build_window_features(df_work: pd.DataFrame) -> pd.DataFrame:
    """Compute the 9 features for every (user, hour-window) in one pass.

    The per-group helper above is the readable reference implementation, but
    calling it once per group means ~10 pandas operations on a handful of rows
    each. At 10k logs that is ~7,700 groups and pandas' per-call overhead
    dominates: it accounted for 19 of 27 seconds in a profile. Aggregating the
    whole frame at once pushes the same work into vectorised C.
    """
    status = df_work["status"].fillna("").str.lower()
    event = df_work["event"].fillna("").str.lower()
    hours = df_work["ts"].dt.hour

    d = df_work.assign(
        _failed_login=((status == "failed") & event.str.contains("login", na=False)),
        _off_hours=((hours >= 22) | (hours < 6)),
        _blocked=(status == "blocked"),
        _privesc=event.isin(["privilege_escalation", "role_elevation"]),
        _export=(event == "export"),
    )
    if "id" not in d.columns:
        d = d.assign(id=0)

    g = d.groupby(["user", "ts_window"], sort=False)
    out = g.agg(
        event_count=("ts", "size"),
        failed_login_count=("_failed_login", "sum"),
        distinct_ips_used=("ip", "nunique"),
        distinct_resources_touched=("resource", "nunique"),
        off_hours_event_ratio=("_off_hours", "mean"),
        blocked_event_ratio=("_blocked", "mean"),
        privilege_change_count=("_privesc", "sum"),
        export_volume=("_export", "sum"),
        _ts_min=("ts", "min"),
        last_ts=("ts", "max"),
        last_ip=("ip", "last"),
        log_id=("id", "last"),
    ).reset_index()

    # Mean gap between events; a single-event window has no gap.
    span = (out["last_ts"] - out["_ts_min"]).dt.total_seconds()
    n = out["event_count"]
    out["avg_time_between_events"] = np.where(n > 1, span / (n - 1).where(n > 1, 1), 0.0).astype(float)
    out = out.drop(columns=["_ts_min"])

    for c in ("failed_login_count", "distinct_ips_used", "distinct_resources_touched",
              "privilege_change_count", "export_volume", "event_count", "log_id"):
        out[c] = out[c].astype(int)
    for c in ("off_hours_event_ratio", "blocked_event_ratio"):
        out[c] = out[c].astype(float)
    out["last_ip"] = out["last_ip"].astype(str)
    return out


def _score_user_windows(user_windows: pd.DataFrame) -> pd.Series:
    """
    Fit an IsolationForest on all of a user's windows and return per-window
    anomaly scores in [0, 1] where 1 = most anomalous relative to that user's
    own history.
    """
    X = user_windows[FEATURE_COLS].values

    # Need at least 4 data points for IsolationForest to be meaningful
    if len(X) < 4:
        # If only 1–3 windows, score them by how extreme they are
        # relative to simple z-score on event_count
        ec = user_windows["event_count"].values.astype(float)
        mean, std = ec.mean(), ec.std()
        if std == 0:
            return pd.Series(np.zeros(len(X)), index=user_windows.index)
        z = np.abs((ec - mean) / std)
        normed = np.clip(z / 3.0, 0, 1)  # 3-sigma → score 1.0
        return pd.Series(normed, index=user_windows.index)

    # More data → use IsolationForest
    # contamination = fraction we expect to be anomalous
    # We keep it low (5%) so normal variation is not penalised.
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        max_samples="auto",
    )
    clf.fit(X)

    raw = clf.decision_function(X)  # higher = more normal
    inv = -raw                       # higher = more anomalous

    lo, hi = inv.min(), inv.max()
    if hi > lo:
        normed = (inv - lo) / (hi - lo)
    else:
        normed = np.zeros(len(inv))

    return pd.Series(normed, index=user_windows.index)


def detect_anomalies(db, df: pd.DataFrame, rule_alerts: list) -> list:
    """
    Main entry point called by the /api/alerts route.

    Parameters
    ----------
    db          : SQLAlchemy session
    df          : full log DataFrame (columns: ts, user, event, resource, ip, status)
    rule_alerts : list of dicts from the rule engine (used to enrich evidence)

    Returns
    -------
    List of alert dicts ready for bulk_insert_mappings(Alert, ...).
    """
    if df.empty:
        return []

    # ── 1. Build per-(user, 1-hour-window) feature rows ─────────────────────
    df_work = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_work["ts"]):
        df_work["ts"] = pd.to_datetime(df_work["ts"], errors="coerce", utc=True)
    df_work = df_work.dropna(subset=["ts"])
    df_work["ts_window"] = df_work["ts"].dt.floor("1h")

    df_work = df_work[df_work["user"].astype(bool)]
    if df_work.empty:
        return []

    all_windows = _build_window_features(df_work)
    if all_windows.empty:
        return []

    # ── 2. Score each user's windows against THEIR OWN history ──────────────
    score_parts = []
    for user, user_df in all_windows.groupby("user"):
        scores = _score_user_windows(user_df)
        user_df = user_df.copy()
        user_df["anomaly_score"] = scores
        score_parts.append(user_df)

    scored = pd.concat(score_parts, ignore_index=True)

    # ── 3. Emit ML alert for every window above the threshold ────────────────
    # Counting a user's windows by filtering the frame inside the loop was a
    # full scan per emitted alert; count once up front instead.
    windows_per_user = scored["user"].value_counts().to_dict()

    ml_alerts = []
    for _, row in scored[scored["anomaly_score"] >= ANOMALY_THRESHOLD].iterrows():
        score  = float(row["anomaly_score"])
        user   = row["user"]

        # Build a human-readable evidence string showing the key signals
        signals = []
        if row["failed_login_count"] > 0:
            signals.append(f"{int(row['failed_login_count'])} failed login(s)")
        if row["distinct_ips_used"] > 1:
            signals.append(f"{int(row['distinct_ips_used'])} different IPs used")
        if row["distinct_resources_touched"] > 3:
            signals.append(f"{int(row['distinct_resources_touched'])} resources accessed")
        if row["off_hours_event_ratio"] > 0.3:
            signals.append(f"{row['off_hours_event_ratio']*100:.0f}% activity outside working hours")
        if row["privilege_change_count"] > 0:
            signals.append(f"{int(row['privilege_change_count'])} privilege escalation event(s)")
        if row["blocked_event_ratio"] > 0.1:
            signals.append(f"{row['blocked_event_ratio']*100:.0f}% of actions were blocked")

        why = ("; ".join(signals) if signals
               else f"{int(row['event_count'])} events in one hour (unusually high for this user)")

        evidence = (
            f"User {user} has ML Anomaly Score {score:.2f} "
            f"(relative to their own {windows_per_user.get(user, 0)} historical hour-windows). "
            f"Key signals: {why}."
        )

        ml_alerts.append({
            "rule_id":        "ml_anomaly_001",
            "rule_name":      "ML Behavioral Anomaly",
            "severity":       "High" if score >= 0.85 else "Medium",
            "points":         int(score * 100),
            "user":           user,
            "ip":             str(row["last_ip"]),
            "timestamp":      row["last_ts"].isoformat() if hasattr(row["last_ts"], "isoformat") else str(row["last_ts"]),
            "log_id":         int(row["log_id"]),
            "ml_anomaly_score": score,
            "evidence":       evidence,
        })

    return ml_alerts
