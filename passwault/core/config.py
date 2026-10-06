"""Application configuration management.

Handles database URL parsing, environment-based configuration and the
filesystem layout for both installed and portable (USB) modes.
"""

import hashlib
import os
import sys
import tempfile
from enum import Enum
from pathlib import Path


class DatabaseType(Enum):
    """Supported database backends."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


class Config:
    """Application configuration from environment variables."""

    # Environment variable names
    ENV_DATABASE_URL = "DATABASE_URL"
    ENV_BACKUP_DIR = "PASSWAULT_BACKUP_DIR"
    ENV_HOME = "PASSWAULT_HOME"
    ENV_XDG_RUNTIME_DIR = "XDG_RUNTIME_DIR"

    # Marker file at the root of a portable bundle
    PORTABLE_MARKER = ".passwault-portable"

    @classmethod
    def get_portable_home(cls) -> Path | None:
        """Get the portable bundle root, or None when running as an installed app.

        PASSWAULT_HOME wins; otherwise a frozen binary at <home>/bin/ detects
        the marker file in its parent directory.
        """
        home = os.environ.get(cls.ENV_HOME)
        if home:
            return Path(home).expanduser().resolve()

        if getattr(sys, "frozen", False):
            candidate = Path(sys.executable).resolve().parent.parent
            if (candidate / cls.PORTABLE_MARKER).is_file():
                return candidate

        return None

    @classmethod
    def is_portable(cls) -> bool:
        """Check if running in portable mode."""
        return cls.get_portable_home() is not None

    @classmethod
    def get_data_dir(cls) -> Path:
        """Get the persistent data directory, creating it if needed."""
        home = cls.get_portable_home()
        if home is not None:
            data_dir = home / "data"
        else:
            data_dir = Path.home() / ".local" / "share" / "passwault"

        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    @classmethod
    def get_state_dir(cls) -> Path:
        """Get the directory for session and decrypted-vault state.

        Installed mode keeps it in the data dir. Portable mode uses a private,
        volatile host directory so no key material lands on the stick.
        """
        home = cls.get_portable_home()
        if home is None:
            return cls.get_data_dir()

        digest = hashlib.sha256(str(home).encode()).hexdigest()[:12]
        state_dir = cls._get_volatile_root() / f"passwault-{digest}"
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        if state_dir.stat().st_uid != os.getuid():
            raise PermissionError(f"State directory not owned by you: {state_dir}")
        state_dir.chmod(0o700)

        return state_dir

    @classmethod
    def _get_volatile_root(cls) -> Path:
        """Pick a RAM-backed, per-user location when one is available."""
        runtime_dir = os.environ.get(cls.ENV_XDG_RUNTIME_DIR)
        if runtime_dir and os.access(runtime_dir, os.W_OK):
            return Path(runtime_dir)

        if os.access("/dev/shm", os.W_OK):
            return Path("/dev/shm")

        return Path(tempfile.gettempdir())

    @classmethod
    def get_database_url(cls) -> str:
        """Get database URL from environment or default to SQLite.

        Portable mode always uses the decrypted vault copy in the state dir.

        Returns:
            Database URL string (SQLite path or PostgreSQL connection string)
        """
        if cls.is_portable():
            return f"sqlite:///{cls.get_state_dir() / 'passwault.db'}"

        database_url = os.environ.get(cls.ENV_DATABASE_URL)

        if database_url:
            return database_url

        # Default to SQLite
        db_path = cls.get_data_dir() / "passwault.db"
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
        home = cls.get_portable_home()
        backup_dir = os.environ.get(cls.ENV_BACKUP_DIR)

        if home is not None:
            path = home / "backups"
        elif backup_dir:
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
