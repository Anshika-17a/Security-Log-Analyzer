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
| `DATABASE_URL` | `sqlite:///./logs.db` | SQLAlchemy URL. Point at Postgres for durable storage. |
| `SEED_ON_START` | `false` | If true, populate an empty DB on boot (see below). |
| `SEED_FILE` | `data/sample_logs.csv` | Which log file to seed from. |
| `GEMINI_API_KEY` | *(unset)* | Enables the AI narrative endpoint. Set it in the Render dashboard — **never commit it**. |

---

## Seeding (why the deployed dashboard isn't empty)

Free tiers use an **ephemeral filesystem**: the SQLite file is destroyed on
every redeploy and every cold start. Without seeding, judges opening the URL
would see an empty dashboard.

With `SEED_ON_START=true`, startup ingests `SEED_FILE`, runs the rule engine,
the ML detector and the correlator — producing **500 logs → 119 alerts →
101 incidents** before the first request is served. It is a no-op if the
database already has logs, so restarts never double-count.

For durable storage instead, attach a Render Disk mounted at `/data` and set
`DATABASE_URL=sqlite:////data/logs.db`, or provision Postgres.

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
