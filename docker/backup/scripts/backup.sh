#!/bin/sh
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/backups/passwault_${TIMESTAMP}.sql.gz"
HOST_BACKUP_FILE="/host-backups/passwault_${TIMESTAMP}.sql.gz"

echo "$(date): Starting backup..."

# Create backup with pg_dump
pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" \
    --format=plain \
    --no-owner \
    --no-privileges \
    | gzip > "$BACKUP_FILE"

# Copy to host-mounted directory
if [ -d "/host-backups" ]; then
    cp "$BACKUP_FILE" "$HOST_BACKUP_FILE"
    echo "$(date): Backup copied to host: $HOST_BACKUP_FILE"
fi

echo "$(date): Backup created: $BACKUP_FILE"

# Cleanup old backups (both in container and host)
echo "$(date): Cleaning up backups older than ${BACKUP_RETENTION_DAYS} days..."

find /backups -name "passwault_*.sql.gz" -type f -mtime +${BACKUP_RETENTION_DAYS} -delete 2>/dev/null || true
find /host-backups -name "passwault_*.sql.gz" -type f -mtime +${BACKUP_RETENTION_DAYS} -delete 2>/dev/null || true

# List current backups
echo "$(date): Current backups:"
ls -lah /backups/*.sql.gz 2>/dev/null || echo "No backups found in container"

echo "$(date): Backup completed successfully"
