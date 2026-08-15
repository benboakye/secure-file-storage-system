#!/bin/sh
set -eu

# Compose mounts the database password as a file. Reading it here prevents the
# credential from being committed to an environment file while preserving the
# URL-based database configuration expected by the application.
password_file="${SECURESTORE_POSTGRES_PASSWORD_FILE:-/run/secrets/postgres_password}"
if [ ! -r "$password_file" ]; then
  echo "SecureStore database password file is missing or unreadable." >&2
  exit 1
fi

postgres_password="$(tr -d '\r\n' < "$password_file")"
if [ -z "$postgres_password" ]; then
  echo "SecureStore database password file is empty." >&2
  exit 1
fi

# init-secrets.ps1 generates a hexadecimal password, so it is safe to place in
# the user-info portion of this internal-only PostgreSQL URL without additional
# percent encoding.
export SECURESTORE_DATABASE_URL="postgres://securestore:${postgres_password}@postgres:5432/securestore?sslmode=disable"
unset postgres_password

exec /usr/local/bin/securestore
