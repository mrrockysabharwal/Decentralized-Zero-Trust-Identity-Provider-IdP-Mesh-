FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system --gid 10001 trustmesh \
    && useradd --system --uid 10001 --gid trustmesh --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin trustmesh \
    && mkdir -p /data \
    && chown trustmesh:trustmesh /data

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 app/ ./app/
COPY --chown=10001:10001 backend/ ./backend/
COPY --chown=10001:10001 frontend/ ./frontend/

ENV WEBAUTHN_DB_PATH=/data/webauthn.sqlite3

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
