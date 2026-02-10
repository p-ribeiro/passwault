"""Unit tests for MigrationService.

Tests database migration from source to a portable SQLite file.
"""

import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from passwault.core.database.models import Base, PasswordManager, User
from passwault.core.services.migration_service import MigrationService


@pytest.fixture
def source_db(monkeypatch):
    """Create a temporary SQLite source database with schema."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "source.db"
        engine = create_engine(f"sqlite:///{db_path}", poolclass=NullPool)

        @event.listens_for(engine, "connect")
        def _set_pragma(dbapi_conn, conn_rec):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)

        monkeypatch.setattr(
            "passwault.core.services.migration_service.SessionLocal", Session
        )

        yield Session, tmpdir


class TestMigrationService:
    """Tests for MigrationService.migrate_to_sqlite."""

    def test_migrate_success(self, source_db):
        """Test successful migration copies users and passwords."""
        Session, tmpdir = source_db
        session = Session()

        session.execute(
            User.__table__.insert().values(
                id=1,
                username="alice",
                email="alice@example.com",
                master_password_hash=b"hash1",
                salt=b"salt1",
                kdf_algorithm="PBKDF2",
                kdf_iterations=600000,
            )
        )
        session.execute(
            PasswordManager.__table__.insert().values(
                id=10,
                user_id=1,
                resource_name="github",
                encrypted_password=b"enc1",
                nonce=b"nonce1",
            )
        )
        session.commit()
        session.close()

        output = Path(tmpdir) / "out" / "migrated.db"
        service = MigrationService()
        result = service.migrate_to_sqlite(str(output))

        assert result == output
        assert output.exists()

        # Verify data in target
        target_engine = create_engine(f"sqlite:///{output}", poolclass=NullPool)
        TargetSession = sessionmaker(bind=target_engine)
        ts = TargetSession()

        users = ts.query(User).all()
        assert len(users) == 1
        assert users[0].username == "alice"

        passwords = ts.query(PasswordManager).all()
        assert len(passwords) == 1
        assert passwords[0].resource_name == "github"
        assert passwords[0].encrypted_password == b"enc1"

        ts.close()
        target_engine.dispose()

    def test_output_exists_raises(self, source_db):
        """Test that FileExistsError is raised when output already exists."""
        _, tmpdir = source_db

        output = Path(tmpdir) / "existing.db"
        output.touch()

        service = MigrationService()
        with pytest.raises(FileExistsError, match="already exists"):
            service.migrate_to_sqlite(str(output))

    def test_empty_database(self, source_db):
        """Test migration of an empty database creates schema but no rows."""
        _, tmpdir = source_db

        output = Path(tmpdir) / "empty.db"
        service = MigrationService()
        service.migrate_to_sqlite(str(output))

        target_engine = create_engine(f"sqlite:///{output}", poolclass=NullPool)
        TargetSession = sessionmaker(bind=target_engine)
        ts = TargetSession()

        assert ts.query(User).count() == 0
        assert ts.query(PasswordManager).count() == 0

        ts.close()
        target_engine.dispose()

    def test_id_preservation(self, source_db):
        """Test that user and password IDs are preserved after migration."""
        Session, tmpdir = source_db
        session = Session()

        session.execute(
            User.__table__.insert().values(
                id=42,
                username="bob",
                master_password_hash=b"hash2",
                salt=b"salt2",
                kdf_algorithm="PBKDF2",
                kdf_iterations=600000,
            )
        )
        session.execute(
            PasswordManager.__table__.insert().values(
                id=99,
                user_id=42,
                resource_name="gitlab",
                encrypted_password=b"enc2",
                nonce=b"nonce2",
            )
        )
        session.commit()
        session.close()

        output = Path(tmpdir) / "ids.db"
        service = MigrationService()
        service.migrate_to_sqlite(str(output))

        target_engine = create_engine(f"sqlite:///{output}", poolclass=NullPool)
        TargetSession = sessionmaker(bind=target_engine)
        ts = TargetSession()

        user = ts.query(User).first()
        assert user.id == 42

        pw = ts.query(PasswordManager).first()
        assert pw.id == 99
        assert pw.user_id == 42

        ts.close()
        target_engine.dispose()

    def test_parent_dir_creation(self, source_db):
        """Test that missing parent directories are created automatically."""
        _, tmpdir = source_db

        output = Path(tmpdir) / "deep" / "nested" / "dir" / "passwault.db"
        service = MigrationService()
        service.migrate_to_sqlite(str(output))

        assert output.exists()
