# Portable alternative to render.yaml — works on Render, Railway, Fly.io,
# Cloud Run, or any container host.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEED_ON_START=true \
    SEED_FILE=data/sample_logs.csv \
    DATABASE_URL=sqlite:///./logs.db

WORKDIR /app

# Dependencies first so layer caching survives source edits
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Hosts inject $PORT; default to 8000 for plain `docker run -p 8000:8000`
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
