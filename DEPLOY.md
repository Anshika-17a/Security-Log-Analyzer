# Deployment Guide

The app is a stateless FastAPI service with a bundled SQLite database. It runs
anywhere that can run `uvicorn`. Two supported paths: **Render Blueprint**
(easiest) or **Docker** (portable).

---

## Option A — Render (recommended)

1. Push this repo to GitHub (`main` branch).
2. Go to <https://dashboard.render.com> → **New** → **Blueprint**.
3. Select this repository. Render reads [`render.yaml`](render.yaml) and
   pre-fills everything — build command, start command, health check, env vars.
4. Click **Apply**. First build takes ~3–5 minutes (compiling nothing; just
   downloading wheels).
5. You get a URL like `https://security-log-analyzer.onrender.com`.

The dashboard will already be populated — see *Seeding* below.

### Free-tier caveat: cold starts

Render's free tier **spins the service down after ~15 minutes of inactivity**.
The next request then takes **~50 seconds** to wake it. For a live demo that is
a bad look. Mitigate with one of:

- **Warm it up 2 minutes before you present** — just open the URL once.
- **Keep it awake** with an external cron pinging `/health` every 10 minutes
  (e.g. a free [cron-job.org](https://cron-job.org) entry).
- **Upgrade to the $7/mo Starter plan** for the duration of the hackathon —
  no spin-down.

---

## Option B — Docker (Railway / Fly.io / Cloud Run / local)

```bash
docker build -t security-log-analyzer .
docker run -p 8000:8000 security-log-analyzer
# -> http://localhost:8000
```

The image pins Python 3.13 and reads `$PORT` if the host injects one, so it
works unmodified on Railway, Fly.io and Cloud Run.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | Injected by the host; uvicorn binds to it. |
| `DATABASE_URL` | `sqlite:///./logs.db` | SQLAlchemy URL. `postgres://` / `postgresql://` are rewritten to psycopg v3 automatically. See **Database**. |
| `SEED_ON_START` | `false` | If true, populate an empty DB on boot (see below). |
| `SEED_FILE` | `data/sample_logs.csv` | Which log file to seed from. |
| `GEMINI_API_KEY` | *(unset)* | Enables the AI narrative endpoint. Set it in the Render dashboard — **never commit it**. |

---

## Database

The app talks to the database through SQLAlchemy, so the storage backend is
purely a matter of `DATABASE_URL`. Two supported dialects:

| Dialect | URL | When |
|---|---|---|
| **SQLite** (default) | `sqlite:///./logs.db` | Local dev. Zero setup, but the file is ephemeral on hosted free tiers. |
| **Postgres** | `postgresql://user:pass@host:5432/dbname` | Anything deployed. Data survives redeploys, cold starts and restarts. |

`app/models/db.py` rewrites `postgres://` and `postgresql://` to the psycopg v3
driver automatically, so you can paste a provider's connection string verbatim —
Render, Heroku and Railway all hand out the legacy `postgres://` scheme that
SQLAlchemy 2 rejects on its own.

**Using Render's blueprint,** nothing needs doing: [`render.yaml`](render.yaml)
provisions a Postgres instance and injects `DATABASE_URL` into the web service.

**Using any other provider** (Neon, Supabase, Railway, a local server), set
`DATABASE_URL` and everything else is unchanged:

```bash
export DATABASE_URL="postgresql://user:pass@host:5432/security_logs"
uvicorn app.main:app --reload
```

Tables are created automatically on startup by `init_db()`. Switching backends
starts from an empty database — there is no migration path between the two, so
re-upload your logs (or let `SEED_ON_START` do it).

> **Render free Postgres expires.** The free instance is deleted after its trial
> window, taking your data with it. Fine for a hackathon. For anything longer
> use Neon or Supabase (free tiers that do not expire), or Render's paid plan.

MySQL is *not* supported as-is: the `EntityBaseline` upsert uses
`ON CONFLICT DO UPDATE` (SQLite/Postgres syntax, MySQL needs
`ON DUPLICATE KEY UPDATE`), and the `String` columns have no length, which MySQL
requires. `app/detection/baseline.py` raises a clear error rather than emitting
broken SQL.

---

## Seeding (why the deployed dashboard isn't empty)

On SQLite, free tiers use an **ephemeral filesystem**: the file is destroyed on
every redeploy and cold start, so judges opening the URL would see an empty
dashboard. On Postgres the data persists and seeding only matters for the very
first boot.

With `SEED_ON_START=true`, startup ingests `SEED_FILE`, runs the rule engine,
the ML detector and the correlator — producing **500 logs → 119 alerts →
101 incidents** before the first request is served. It is a no-op if the
database already has logs, so restarts never double-count.

To keep SQLite but make it durable, attach a Render Disk mounted at `/data` and
set `DATABASE_URL=sqlite:////data/logs.db`. Postgres (above) is the better
default and is what the blueprint provisions.

---

## ⚠️ Before exposing this publicly

The app currently has **no authentication** and CORS is wide open
(`allow_origins=["*"]` in [`app/main.py`](app/main.py)). Anyone with the URL can:

- upload arbitrary log files,
- read every incident and its evidence,
- change incident statuses.

That is fine for a time-boxed hackathon demo with synthetic data. Do **not**
put real security logs behind it as-is. The minimum hardening would be an API
key dependency on the write endpoints and restricting `allow_origins` to the
deployed domain.
