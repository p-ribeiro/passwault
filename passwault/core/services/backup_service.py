"""Backup service for database backup and restore operations.

Supports both SQLite (file copy) and PostgreSQL (pg_dump) backups.
"""

import gzip
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from passwault.core.config import Config, DatabaseType


class BackupService:
    """Service for database backup operations."""

    def __init__(self, backup_dir: Optional[Path] = None):
        """Initialize backup service.

        Args:
            backup_dir: Custom backup directory (uses config default if None)
        """
        self.backup_dir = backup_dir or Config.get_backup_dir()
        self.database_type = Config.get_database_type()
        self.database_url = Config.get_database_url()

    def create_backup(self, compress: bool = True) -> Path:
        """Create a database backup.

        Args:
            compress: Whether to gzip the backup (default: True)

        Returns:
            Path to the created backup file

        Raises:
            RuntimeError: If backup fails
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if self.database_type == DatabaseType.SQLITE:
            return self._backup_sqlite(timestamp, compress)
        else:
            return self._backup_postgresql(timestamp, compress)

    def _backup_sqlite(self, timestamp: str, compress: bool) -> Path:
        """Create SQLite backup by copying the database file.

        Args:
            timestamp: Backup timestamp string
            compress: Whether to compress the backup

        Returns:
            Path to backup file
        """
        # Extract path from sqlite:///path URL
        db_path = Path(self.database_url.replace("sqlite:///", ""))

        if not db_path.exists():
            raise RuntimeError(f"Database file not found: {db_path}")

        if compress:
            backup_file = self.backup_dir / f"passwault_{timestamp}.db.gz"
            with open(db_path, "rb") as f_in:
                with gzip.open(backup_file, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            backup_file = self.backup_dir / f"passwault_{timestamp}.db"
            shutil.copy2(db_path, backup_file)

        return backup_file

    def _backup_postgresql(self, timestamp: str, compress: bool) -> Path:
        """Create PostgreSQL backup using pg_dump.

        Args:
            timestamp: Backup timestamp string
            compress: Whether to compress the backup

        Returns:
            Path to backup file

        Raises:
            RuntimeError: If pg_dump fails or is not available
        """
        # Check if pg_dump is available
        if shutil.which("pg_dump") is None:
            raise RuntimeError(
                "pg_dump not found. Install PostgreSQL client tools to use backup feature."
            )

        # Parse PostgreSQL connection URL
        parsed = urlparse(self.database_url)

        env = {
            **os.environ,
            "PGPASSWORD": parsed.password or "",
        }

        cmd = [
            "pg_dump",
            "-h",
            parsed.hostname or "localhost",
            "-p",
            str(parsed.port or 5432),
            "-U",
            parsed.username or "passwault",
            "-d",
            parsed.path.lstrip("/"),
            "--format=plain",
            "--no-owner",
            "--no-privileges",
        ]

        if compress:
            backup_file = self.backup_dir / f"passwault_{timestamp}.sql.gz"
            result = subprocess.run(
                cmd,
                capture_output=True,
                env=env,
            )
            if result.returncode != 0:
                raise RuntimeError(f"pg_dump failed: {result.stderr.decode()}")

            with gzip.open(backup_file, "wb") as f:
                f.write(result.stdout)
        else:
            backup_file = self.backup_dir / f"passwault_{timestamp}.sql"
            with open(backup_file, "wb") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    env=env,
                )

            if result.returncode != 0:
                backup_file.unlink(missing_ok=True)
                raise RuntimeError(f"pg_dump failed: {result.stderr.decode()}")

        return backup_file

    def list_backups(self) -> List[Path]:
        """List all available backups.

        Returns:
            List of backup file paths, sorted by modification time (newest first)
        """
        patterns = [
            "passwault_*.db",
            "passwault_*.db.gz",
            "passwault_*.sql",
            "passwault_*.sql.gz",
        ]

        backups = []
        for pattern in patterns:
            backups.extend(self.backup_dir.glob(pattern))

        return sorted(backups, key=lambda p: p.stat().st_mtime, reverse=True)

    def restore_backup(self, backup_path: Path) -> None:
        """Restore database from a backup file.

        Args:
            backup_path: Path to the backup file

        Raises:
            RuntimeError: If restore fails
            ValueError: If backup file type doesn't match database type
        """
        if not backup_path.exists():
            raise RuntimeError(f"Backup file not found: {backup_path}")

        # Determine backup type from filename
        name = backup_path.name
        if ".db.gz" in name or name.endswith(".db"):
            backup_type = DatabaseType.SQLITE
        elif ".sql.gz" in name or name.endswith(".sql"):
            backup_type = DatabaseType.POSTGRESQL
        else:
            raise ValueError(f"Unknown backup file type: {backup_path}")

        if backup_type != self.database_type:
            raise ValueError(
                f"Backup type ({backup_type.value}) doesn't match "
                f"current database ({self.database_type.value})"
            )

        if backup_type == DatabaseType.SQLITE:
            self._restore_sqlite(backup_path)
        else:
            self._restore_postgresql(backup_path)

    def _restore_sqlite(self, backup_path: Path) -> None:
        """Restore SQLite database from backup."""
        db_path = Path(self.database_url.replace("sqlite:///", ""))

        # Create backup of current database
        if db_path.exists():
            current_backup = db_path.with_suffix(".db.bak")
            shutil.copy2(db_path, current_backup)

        # Restore
        if backup_path.suffix == ".gz":
            with gzip.open(backup_path, "rb") as f_in:
                with open(db_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            shutil.copy2(backup_path, db_path)

    def _restore_postgresql(self, backup_path: Path) -> None:
        """Restore PostgreSQL database from backup."""
        # Check if psql is available
        if shutil.which("psql") is None:
            raise RuntimeError(
                "psql not found. Install PostgreSQL client tools to use restore feature."
            )

        parsed = urlparse(self.database_url)

        env = {
            **os.environ,
            "PGPASSWORD": parsed.password or "",
        }

        cmd = [
            "psql",
            "-h",
            parsed.hostname or "localhost",
            "-p",
            str(parsed.port or 5432),
            "-U",
            parsed.username or "passwault",
            "-d",
            parsed.path.lstrip("/"),
        ]

        if backup_path.suffix == ".gz":
            with gzip.open(backup_path, "rt") as f:
                result = subprocess.run(
                    cmd,
                    stdin=f,
                    capture_output=True,
                    env=env,
                    text=True,
                )
        else:
            with open(backup_path, "r") as f:
                result = subprocess.run(
                    cmd,
                    stdin=f,
                    capture_output=True,
                    env=env,
                    text=True,
                )

        if result.returncode != 0:
            raise RuntimeError(f"psql restore failed: {result.stderr}")

    def cleanup_old_backups(self, retention_days: int = 30) -> int:
        """Remove backups older than retention period.

        Args:
            retention_days: Number of days to retain backups

        Returns:
            Number of backups removed
        """
        cutoff = datetime.now() - timedelta(days=retention_days)
        removed = 0

        for backup in self.list_backups():
            if datetime.fromtimestamp(backup.stat().st_mtime) < cutoff:
                backup.unlink()
                removed += 1

        return removed
