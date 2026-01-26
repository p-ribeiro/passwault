#!/bin/sh
set -e

echo "Starting backup scheduler..."
echo "Schedule: $BACKUP_SCHEDULE"
echo "Retention: $BACKUP_RETENTION_DAYS days"

# Install required packages
apk add --no-cache dcron

# Create cron job
echo "$BACKUP_SCHEDULE /scripts/backup.sh >> /var/log/backup.log 2>&1" > /etc/crontabs/root

# Ensure log file exists
touch /var/log/backup.log

# Run initial backup
echo "Running initial backup..."
/scripts/backup.sh

# Start cron daemon in foreground
echo "Starting cron daemon..."
crond -f -l 2
