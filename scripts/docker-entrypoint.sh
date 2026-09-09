#!/bin/bash
set -e

# Create necessary directories
mkdir -p /data/uploads /data/instance
chmod 755 /data/uploads /data/instance

# KCS hardening note: the -lite image purges libsqlite3-0 (KCS High findings),
# so a sqlite:// URI cannot work there. Fail with a clear, actionable message
# instead of an ImportError from deep inside SQLAlchemy. No-op on the full
# image and on any Postgres URI (sqlite3 import is only probed for sqlite URIs).
if [[ "${SQLALCHEMY_DATABASE_URI:-}" == sqlite:* ]]; then
    if ! python -c "import sqlite3" 2>/dev/null; then
        echo "ERROR: SQLALCHEMY_DATABASE_URI points at SQLite, but this image" >&2
        echo "       has no SQLite support (KCS hardening purged libsqlite3-0)." >&2
        echo "       Set SQLALCHEMY_DATABASE_URI to a PostgreSQL URI" >&2
        echo "       (postgresql://user:pass@host:port/dbname)." >&2
        exit 1
    fi
fi

# Initialize the database if it doesn't exist
if [ ! -f /data/instance/transcriptions.db ]; then
    echo "Database doesn't exist. Creating new database..."
    python -c "from src.app import app, db; app.app_context().push(); db.create_all()"
    echo "Database created successfully."
else
    echo "Database exists. Checking for schema updates..."
    python -c "from src.app import app; app.app_context().push()"
fi

# Check if we need to create an admin user (regardless of whether the database exists)
if [ -n "$ADMIN_USERNAME" ] && [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "Creating admin user using environment variables..."
    cd /app && python scripts/docker_create_admin.py
fi

# Start the application
exec "$@"
