#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"
RECOVERY_FILE="$ROOT_DIR/initial-recovery-codes.txt"
CREATED_ENV=false
GENERATED_PASSWORD=""

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: ./install.sh

Creates .env from .env.example when needed, generates unique local secrets,
pulls PostgreSQL and ClamAV, builds the API/frontend image, starts the stack,
and waits until the web readiness check succeeds.

An existing .env is never overwritten.
EOF
}

replace_env_value() {
  local key="$1"
  local value="$2"
  local temporary
  temporary="$(mktemp "$ROOT_DIR/.env.tmp.XXXXXX")"

  awk -v key="$key" -v value="$value" '
    BEGIN { prefix = key "="; replaced = 0 }
    index($0, prefix) == 1 {
      if (!replaced) print prefix value
      replaced = 1
      next
    }
    { print }
    END {
      if (!replaced) print prefix value
    }
  ' "$ENV_FILE" > "$temporary"

  chmod 600 "$temporary"
  mv "$temporary" "$ENV_FILE"
}

read_env_value() {
  local key="$1"
  awk -v key="$key" '
    BEGIN { prefix = key "=" }
    index($0, prefix) == 1 {
      print substr($0, length(prefix) + 1)
      exit
    }
  ' "$ENV_FILE"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command '$1' was not found. $2"
}

show_diagnostics() {
  log ""
  log "Current service status:"
  "${COMPOSE[@]}" ps || true
  log ""
  log "Recent API and dependency logs:"
  "${COMPOSE[@]}" logs --tail=120 api worker clamav postgres || true
}

service_is_running() {
  local service="$1"
  local container_id
  local running_state
  container_id="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)"
  [[ -n "$container_id" ]] || return 1
  running_state="$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)"
  [[ "$running_state" == "true" ]]
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  die "Unknown arguments: $*"
fi

cd "$ROOT_DIR"

require_command docker "Install Docker Engine or Docker Desktop."
require_command openssl "Install the OpenSSL command-line package."
require_command curl "Install curl."
require_command awk "Install a standard awk implementation."
require_command mktemp "Install coreutils or the equivalent host utility."

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose --project-directory "$ROOT_DIR" --file "$ROOT_DIR/docker-compose.yml")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose --project-directory "$ROOT_DIR" --file "$ROOT_DIR/docker-compose.yml")
else
  die "Docker Compose was not found. Install the Docker Compose v2 plugin."
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker is installed but its daemon is unavailable. Start Docker and check your user permissions."
fi

[[ -f "$ROOT_DIR/.env.example" ]] || die ".env.example is missing from $ROOT_DIR"
[[ -f "$ROOT_DIR/docker-compose.yml" ]] || die "docker-compose.yml is missing from $ROOT_DIR"

if [[ -L "$ENV_FILE" ]]; then
  die ".env must not be a symbolic link"
elif [[ -e "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || die ".env exists but is not a regular file"
  log "Using existing .env; its values will not be overwritten."
else
  log "Creating a new .env with unique local secrets..."
  cp "$ROOT_DIR/.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  CREATED_ENV=true

  database_password="$(openssl rand -hex 24)"
  app_key="$(openssl rand -base64 32 | tr -d '\r\n')"
  backup_key="$(openssl rand -base64 32 | tr -d '\r\n')"
  GENERATED_PASSWORD="Em!$(openssl rand -hex 14)"

  replace_env_value POSTGRES_PASSWORD "$database_password"
  replace_env_value DATABASE_URL "postgresql+psycopg://exception_manager:${database_password}@postgres:5432/exception_manager"
  replace_env_value APP_ENCRYPTION_KEY "$app_key"
  replace_env_value BACKUP_ENCRYPTION_KEY "$backup_key"
  replace_env_value BREAK_GLASS_INITIAL_PASSWORD "$GENERATED_PASSWORD"
fi

chmod 600 "$ENV_FILE"

for required_key in POSTGRES_PASSWORD DATABASE_URL APP_ENCRYPTION_KEY BACKUP_ENCRYPTION_KEY; do
  required_value="$(read_env_value "$required_key" || true)"
  [[ -n "$required_value" ]] || die ".env key '$required_key' is missing or empty"
done

username="$(read_env_value BREAK_GLASS_USERNAME || true)"
[[ -n "$username" ]] || die ".env key 'BREAK_GLASS_USERNAME' is missing or empty"

environment="$(read_env_value ENVIRONMENT || true)"
environment="${environment:-development}"
[[ "$environment" == "development" ]] || die "install.sh supports local development only; ENVIRONMENT must be 'development'"

app_port="$(read_env_value APP_PORT || true)"
app_port="${app_port:-8000}"
[[ "$app_port" =~ ^[0-9]+$ ]] || die "APP_PORT must be a number"
(( app_port >= 1 && app_port <= 65535 )) || die "APP_PORT must be between 1 and 65535"

app_bind_address="$(read_env_value APP_BIND_ADDRESS || true)"
app_bind_address="${app_bind_address:-127.0.0.1}"
[[ -n "$app_bind_address" ]] || die "APP_BIND_ADDRESS must not be empty"

log "Validating Compose configuration..."
if ! "${COMPOSE[@]}" config >/dev/null; then
  die "Docker Compose could not read or validate $ROOT_DIR/docker-compose.yml"
fi

log "Pulling PostgreSQL and ClamAV images..."
"${COMPOSE[@]}" pull postgres clamav

log "Building the backend and frontend image..."
if ! "${COMPOSE[@]}" build api; then
  die "Docker Compose could not build the application image"
fi

if ! "${COMPOSE[@]}" up -d; then
  show_diagnostics
  die "Docker Compose could not start the application"
fi

log "Waiting for the application readiness check (initial ClamAV setup can take several minutes)..."
deadline=$((SECONDS + 900))
ready_url="http://127.0.0.1:${app_port}/ready"
while ! curl --fail --silent --show-error --max-time 5 "$ready_url" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    show_diagnostics
    die "The application did not become ready within 15 minutes"
  fi
  printf '.'
  sleep 5
done
printf '\n'

worker_deadline=$((SECONDS + 60))
until service_is_running worker; do
  if (( SECONDS >= worker_deadline )); then
    show_diagnostics
    die "The worker did not remain running for 60 seconds"
  fi
  sleep 2
done

health_response="$(curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${app_port}/health")"
[[ "$health_response" == '{"status":"ok"}' ]] || die "Unexpected health response: $health_response"

curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${app_port}/" \
  | grep --quiet '<title>Exception Manager</title>' \
  || die "The web application HTML was not served correctly"

if [[ "$CREATED_ENV" == true ]]; then
  "${COMPOSE[@]}" logs --no-color --tail=500 api \
    | awk '
        /Break-glass recovery codes/ { capture = 1; remaining = 11 }
        remaining > 0 { print; remaining-- }
      ' > "$RECOVERY_FILE" || true
  if [[ -s "$RECOVERY_FILE" ]]; then
    chmod 600 "$RECOVERY_FILE"
  else
    rm -f "$RECOVERY_FILE"
  fi
fi

log ""
log "Installation completed successfully."
log "Web application: http://localhost:${app_port}"
log "Health check:     http://localhost:${app_port}/health"
log "Break-glass user: ${username}"

if [[ "$CREATED_ENV" == true ]]; then
  log "Temporary password: ${GENERATED_PASSWORD}"
  log "Change it immediately after the first login, then clear BREAK_GLASS_INITIAL_PASSWORD from .env."
  if [[ -f "$RECOVERY_FILE" ]]; then
    log "Recovery codes were saved to: $RECOVERY_FILE"
    log "Move them to an approved password vault, then delete the local file."
  else
    warn "No first-login recovery-code marker was found; an existing database may already have been reused."
  fi
else
  log "Existing credentials are unchanged."
fi

if [[ "$app_bind_address" != "127.0.0.1" && "$app_bind_address" != "localhost" ]]; then
  warn "The application is bound to ${app_bind_address}. Restrict access with a firewall or trusted reverse proxy."
fi

"${COMPOSE[@]}" ps
