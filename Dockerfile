# syntax=docker/dockerfile:1.7
FROM python:3.12.9-slim-bookworm AS python-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
COPY backend/requirements.txt /build/requirements.txt
RUN /opt/venv/bin/pip install -r requirements.txt

FROM node:20.20.2-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM python:3.12.9-slim-bookworm AS runtime
ARG APP_UID=10001
ARG APP_GID=10001
ARG POSTGRES_CLIENT_MAJOR=17
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl libmagic1 xmlsec1 libxmlsec1-openssl \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       -o /etc/apt/keyrings/postgresql.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/postgresql.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y "postgresql-client-${POSTGRES_CLIENT_MAJOR}" \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app/backend
COPY --from=python-builder /opt/venv /opt/venv
COPY --chown=app:app backend/ /app/backend/
COPY --chown=app:app --from=frontend-builder /build/dist /app/frontend/dist
RUN mkdir -p /app/storage /app/data && chown -R app:app /app/storage /app/data
USER app
EXPOSE 8000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
