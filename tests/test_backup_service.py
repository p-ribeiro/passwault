"""Tests for backup service."""

import os
import tempfile
import time
from pathlib import Path

import pytest

from passwault.core.config import Config, DatabaseType
from passwault.core.services.backup_service import BackupService


@pytest.fixture
def temp_backup_dir():
    """Create temporary backup directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_sqlite_db(temp_backup_dir):
    """Create a mock SQLite database file."""
    db_path = temp_backup_dir / "test.db"
    # Create a minimal SQLite database
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO test (name) VALUES ('test_data')")
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def mock_sqlite_config(monkeypatch, mock_sqlite_db, temp_backup_dir):
    """Mock configuration for SQLite testing."""
    backup_dir = temp_backup_dir / "backups"
    backup_dir.mkdir(exist_ok=True)

    monkeypatch.setattr(
        Config, "get_database_url", lambda: f"sqlite:///{mock_sqlite_db}"
    )
    monkeypatch.setattr(Config, "get_database_type", lambda: DatabaseType.SQLITE)
    monkeypatch.setattr(Config, "get_backup_dir", lambda: backup_dir)

    return mock_sqlite_db, backup_dir


class TestBackupServiceInit:
    """Test BackupService initialization."""

    def test_init_with_default_backup_dir(self, mock_sqlite_config):
        """Test initialization with default backup directory."""
        _, backup_dir = mock_sqlite_config
        service = BackupService()

        assert service.backup_dir == backup_dir
        assert service.database_type == DatabaseType.SQLITE

    def test_init_with_custom_backup_dir(self, mock_sqlite_config, temp_backup_dir):
        """Test initialization with custom backup directory."""
        custom_dir = temp_backup_dir / "custom_backups"
        custom_dir.mkdir(exist_ok=True)

        service = BackupService(backup_dir=custom_dir)

        assert service.backup_dir == custom_dir


class TestSQLiteBackup:
    """Test SQLite backup operations."""

    def test_create_backup_compressed(self, mock_sqlite_config, temp_backup_dir):
        """Test creating compressed SQLite backup."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        backup_path = service.create_backup(compress=True)

        assert backup_path.exists()
        assert backup_path.suffix == ".gz"
        assert "passwault_" in backup_path.name
        assert backup_path.stat().st_size > 0

    def test_create_backup_uncompressed(self, mock_sqlite_config, temp_backup_dir):
        """Test creating uncompressed SQLite backup."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        backup_path = service.create_backup(compress=False)

        assert backup_path.exists()
        assert backup_path.suffix == ".db"
        assert "passwault_" in backup_path.name

    def test_create_backup_missing_database(self, monkeypatch, temp_backup_dir):
        """Test backup fails when database file doesn't exist."""
        nonexistent_db = temp_backup_dir / "nonexistent.db"
        backup_dir = temp_backup_dir / "backups"
        backup_dir.mkdir(exist_ok=True)

        monkeypatch.setattr(
            Config, "get_database_url", lambda: f"sqlite:///{nonexistent_db}"
        )
        monkeypatch.setattr(Config, "get_database_type", lambda: DatabaseType.SQLITE)
        monkeypatch.setattr(Config, "get_backup_dir", lambda: backup_dir)

        service = BackupService()

        with pytest.raises(RuntimeError, match="Database file not found"):
            service.create_backup()


class TestListBackups:
    """Test backup listing."""

    def test_list_backups_empty(self, mock_sqlite_config):
        """Test listing when no backups exist."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        backups = service.list_backups()

        assert len(backups) == 0

    def test_list_backups_multiple(self, mock_sqlite_config):
        """Test listing multiple backups."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create multiple backups with different names manually
        backup1 = service.create_backup()
        time.sleep(1.1)  # Ensure different timestamps (need > 1 second)
        backup2 = service.create_backup()

        backups = service.list_backups()

        assert len(backups) == 2
        # Newest first
        assert backups[0] == backup2
        assert backups[1] == backup1

    def test_list_backups_filters_by_pattern(self, mock_sqlite_config, temp_backup_dir):
        """Test that only passwault backup files are listed."""
        _, backup_dir = mock_sqlite_config

        # Create a non-backup file
        other_file = backup_dir / "other_file.txt"
        other_file.write_text("not a backup")

        service = BackupService(backup_dir=backup_dir)
        service.create_backup()

        backups = service.list_backups()

        assert len(backups) == 1
        assert "passwault_" in backups[0].name


class TestRestoreBackup:
    """Test backup restoration."""

    def test_restore_sqlite_backup_uncompressed(self, mock_sqlite_config):
        """Test restoring uncompressed SQLite backup."""
        db_path, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create backup
        backup_path = service.create_backup(compress=False)

        # Modify original database
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM test")
        conn.commit()
        conn.close()

        # Restore
        service.restore_backup(backup_path)

        # Verify data is restored
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT name FROM test")
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == 1
        assert rows[0][0] == "test_data"

    def test_restore_sqlite_backup_compressed(self, mock_sqlite_config):
        """Test restoring compressed SQLite backup."""
        db_path, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create backup
        backup_path = service.create_backup(compress=True)

        # Modify original database
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM test")
        conn.commit()
        conn.close()

        # Restore
        service.restore_backup(backup_path)

        # Verify data is restored
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT name FROM test")
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == 1

    def test_restore_creates_backup_of_current(self, mock_sqlite_config):
        """Test that restore creates backup of current database."""
        db_path, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create and restore backup
        backup_path = service.create_backup(compress=False)
        service.restore_backup(backup_path)

        # Check that .bak file was created
        bak_file = db_path.with_suffix(".db.bak")
        assert bak_file.exists()

    def test_restore_nonexistent_backup(self, mock_sqlite_config, temp_backup_dir):
        """Test restore fails for nonexistent backup file."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        nonexistent = temp_backup_dir / "nonexistent.db"

        with pytest.raises(RuntimeError, match="Backup file not found"):
            service.restore_backup(nonexistent)

    def test_restore_wrong_database_type(self, mock_sqlite_config, temp_backup_dir):
        """Test restore fails when backup type doesn't match database type."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create a fake PostgreSQL backup file
        fake_pg_backup = backup_dir / "passwault_test.sql"
        fake_pg_backup.write_text("-- fake postgres backup")

        with pytest.raises(ValueError, match="doesn't match"):
            service.restore_backup(fake_pg_backup)


class TestCleanupBackups:
    """Test backup cleanup."""

    def test_cleanup_removes_old_backups(self, mock_sqlite_config):
        """Test that old backups are removed."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create a backup
        backup_path = service.create_backup()

        # Artificially age the backup (31 days)
        old_time = time.time() - (31 * 24 * 60 * 60)
        os.utime(backup_path, (old_time, old_time))

        # Cleanup with 30 day retention
        removed = service.cleanup_old_backups(retention_days=30)

        assert removed == 1
        assert not backup_path.exists()

    def test_cleanup_keeps_recent_backups(self, mock_sqlite_config):
        """Test that recent backups are kept."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create a backup (will be recent)
        backup_path = service.create_backup()

        # Cleanup with 30 day retention
        removed = service.cleanup_old_backups(retention_days=30)

        assert removed == 0
        assert backup_path.exists()

    def test_cleanup_with_mixed_ages(self, mock_sqlite_config):
        """Test cleanup with mix of old and new backups."""
        _, backup_dir = mock_sqlite_config
        service = BackupService(backup_dir=backup_dir)

        # Create old backup
        old_backup = service.create_backup()
        old_time = time.time() - (31 * 24 * 60 * 60)
        os.utime(old_backup, (old_time, old_time))

        # Create new backup (wait for different timestamp)
        time.sleep(1.1)
        new_backup = service.create_backup()

        # Cleanup
        removed = service.cleanup_old_backups(retention_days=30)

        assert removed == 1
        assert not old_backup.exists()
        assert new_backup.exists()
