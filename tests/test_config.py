"""Tests for configuration module."""

import tempfile
from pathlib import Path

import pytest

from passwault.core.config import Config, DatabaseType


class TestConfig:
    """Test suite for Config class."""

    def test_default_database_url_is_sqlite(self, monkeypatch):
        """Test that default database URL uses SQLite."""
        monkeypatch.delenv("DATABASE_URL", raising=False)

        url = Config.get_database_url()

        assert url.startswith("sqlite:///")
        assert "passwault.db" in url

    def test_database_url_from_environment(self, monkeypatch):
        """Test that DATABASE_URL environment variable is respected."""
        test_url = "postgresql://user:pass@localhost:5432/testdb"
        monkeypatch.setenv("DATABASE_URL", test_url)

        url = Config.get_database_url()

        assert url == test_url

    def test_database_type_sqlite(self, monkeypatch):
        """Test SQLite database type detection."""
        monkeypatch.delenv("DATABASE_URL", raising=False)

        db_type = Config.get_database_type()

        assert db_type == DatabaseType.SQLITE

    def test_database_type_postgresql(self, monkeypatch):
        """Test PostgreSQL database type detection."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/test")

        db_type = Config.get_database_type()

        assert db_type == DatabaseType.POSTGRESQL

    def test_database_type_postgres_short_scheme(self, monkeypatch):
        """Test PostgreSQL detection with 'postgres://' scheme."""
        monkeypatch.setenv("DATABASE_URL", "postgres://localhost/test")

        db_type = Config.get_database_type()

        assert db_type == DatabaseType.POSTGRESQL

    def test_database_type_unsupported(self, monkeypatch):
        """Test that unsupported database scheme raises ValueError."""
        monkeypatch.setenv("DATABASE_URL", "mysql://localhost/test")

        with pytest.raises(ValueError, match="Unsupported database URL scheme"):
            Config.get_database_type()

    def test_default_backup_dir(self, monkeypatch):
        """Test default backup directory."""
        monkeypatch.delenv("PASSWAULT_BACKUP_DIR", raising=False)

        backup_dir = Config.get_backup_dir()

        expected = Path.home() / ".passwault" / "backups"
        assert backup_dir == expected
        assert backup_dir.exists()

    def test_backup_dir_from_environment(self, monkeypatch):
        """Test backup directory from environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("PASSWAULT_BACKUP_DIR", tmpdir)

            backup_dir = Config.get_backup_dir()

            assert backup_dir == Path(tmpdir)

    def test_backup_dir_creates_directory(self, monkeypatch):
        """Test that backup directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "new" / "backup" / "dir"
            monkeypatch.setenv("PASSWAULT_BACKUP_DIR", str(new_dir))

            backup_dir = Config.get_backup_dir()

            assert backup_dir.exists()
            assert backup_dir == new_dir

    def test_is_postgresql(self, monkeypatch):
        """Test is_postgresql helper method."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/test")
        assert Config.is_postgresql() is True

        monkeypatch.delenv("DATABASE_URL")
        assert Config.is_postgresql() is False

    def test_is_sqlite(self, monkeypatch):
        """Test is_sqlite helper method."""
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert Config.is_sqlite() is True

        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/test")
        assert Config.is_sqlite() is False
