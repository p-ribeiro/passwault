"""Application configuration management.

Handles database URL parsing and environment-based configuration.
"""

import os
from enum import Enum
from pathlib import Path

from passwault.core.utils.data_dir import get_data_dir


class DatabaseType(Enum):
    """Supported database backends."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


class Config:
    """Application configuration from environment variables."""

    # Environment variable names
    ENV_DATABASE_URL = "DATABASE_URL"
    ENV_BACKUP_DIR = "PASSWAULT_BACKUP_DIR"

    @classmethod
    def get_database_url(cls) -> str:
        """Get database URL from environment or default to SQLite.

        Returns:
            Database URL string (SQLite path or PostgreSQL connection string)
        """
        database_url = os.environ.get(cls.ENV_DATABASE_URL)

        if database_url:
            return database_url

        # Default to SQLite
        db_path = get_data_dir() / "passwault.db"
        return f"sqlite:///{db_path}"

    @classmethod
    def get_database_type(cls) -> DatabaseType:
        """Determine database type from URL.

        Returns:
            DatabaseType enum value

        Raises:
            ValueError: If database URL scheme is not supported
        """
        url = cls.get_database_url()

        if url.startswith("sqlite"):
            return DatabaseType.SQLITE
        elif url.startswith("postgresql") or url.startswith("postgres"):
            return DatabaseType.POSTGRESQL
        else:
            raise ValueError(f"Unsupported database URL scheme: {url}")

    @classmethod
    def get_backup_dir(cls) -> Path:
        """Get backup directory from environment or default.

        Returns:
            Path to backup directory
        """
        backup_dir = os.environ.get(cls.ENV_BACKUP_DIR)

        if backup_dir:
            path = Path(backup_dir)
        else:
            path = Path.home() / ".passwault" / "backups"

        path.mkdir(parents=True, exist_ok=True)
        return path

    @classmethod
    def is_postgresql(cls) -> bool:
        """Check if using PostgreSQL backend."""
        return cls.get_database_type() == DatabaseType.POSTGRESQL

    @classmethod
    def is_sqlite(cls) -> bool:
        """Check if using SQLite backend."""
        return cls.get_database_type() == DatabaseType.SQLITE
