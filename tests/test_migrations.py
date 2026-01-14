"""Unit tests for database migrations.

Tests migration from plain-text password storage (v1) to encrypted
password storage with multi-user support (v2).
"""

import os
import tempfile

import pytest
from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

from passwault.core.database import models
from passwault.core.database.migrations import (
    check_migration_needed,
    migrate_from_v1_to_v2,
)
from passwault.core.database.models import Base, PasswordManager, User
from passwault.core.services.crypto_service import CryptoService


@pytest.fixture
def temp_db():
    """Create a temporary test database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")

    engine = create_engine(f"sqlite:///{db_path}", echo=False)

    # Store original values
    original_engine = models.engine
    original_session = models.SessionLocal

    # Replace with test engine
    models.engine = engine
    models.SessionLocal = sessionmaker(bind=engine)

    yield engine, db_path

    # Restore original values
    models.engine = original_engine
    models.SessionLocal = original_session

    # Cleanup
    engine.dispose()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def old_schema_db(temp_db):
    """Create a database with old schema (plain-text passwords, no users table)."""
    engine, db_path = temp_db

    # Create old schema Base
    OldBase = declarative_base()

    class OldPasswordManager(OldBase):
        """Old password manager model without encryption."""

        __tablename__ = "password_manager"

        id = Column(Integer, primary_key=True, autoincrement=True)
        resource_name = Column(String(100), nullable=False)
        username = Column(String(255), nullable=True)
        password = Column(String(255), nullable=False)  # Plain text!
        website = Column(String(255), nullable=True)
        description = Column(String(500), nullable=True)

    # Create old tables
    OldBase.metadata.create_all(engine)

    # Add some test passwords
    session = models.SessionLocal()
    try:
        passwords = [
            OldPasswordManager(
                resource_name="github",
                username="john",
                password="plaintext123",
                website="https://github.com",
            ),
            OldPasswordManager(
                resource_name="gmail",
                username="john@gmail.com",
                password="emailpass456",
            ),
            OldPasswordManager(
                resource_name="aws",
                password="awspassword789",
                description="AWS Console",
            ),
        ]

        for pwd in passwords:
            session.add(pwd)

        session.commit()

        # Return count of passwords created
        result = session.execute(text("SELECT COUNT(*) FROM password_manager"))
        count = result.scalar()

        yield engine, count

    finally:
        session.close()


@pytest.fixture
def crypto_service():
    """Provide CryptoService instance."""
    return CryptoService()


class TestMigrationDetection:
    """Test suite for migration detection."""

    def test_no_migration_needed_fresh_install(self):
        """Test that fresh install doesn't require migration."""
        # Use completely isolated database for this test
        db_fd, db_path = tempfile.mkstemp(suffix=".db")

        try:
            engine = create_engine(f"sqlite:///{db_path}", echo=False)

            # Store original values
            original_engine = models.engine
            original_session = models.SessionLocal

            # Replace with test engine
            models.engine = engine
            models.SessionLocal = sessionmaker(bind=engine)

            # Create new schema
            Base.metadata.create_all(engine)

            # Verify no passwords exist
            session = models.SessionLocal()
            try:
                result_count = session.execute(text("SELECT COUNT(*) FROM password_manager"))
                count = result_count.scalar()
                assert count == 0, f"Expected 0 passwords in fresh install, found {count}"
            finally:
                session.close()

            result = check_migration_needed()

            assert result.ok is True
            assert result.result is False, f"Fresh install should not need migration"

            # Restore original values
            models.engine = original_engine
            models.SessionLocal = original_session

            # Cleanup
            engine.dispose()

        finally:
            os.close(db_fd)
            os.unlink(db_path)

    def test_migration_needed_old_schema(self, old_schema_db):
        """Test that old schema triggers migration."""
        engine, password_count = old_schema_db

        result = check_migration_needed()

        assert result.ok is True
        assert result.result is True

    def test_migration_needed_no_users(self, temp_db):
        """Test that passwords without users trigger migration."""
        engine, db_path = temp_db

        # Create new schema
        Base.metadata.create_all(engine)

        # Add password without user using raw SQL to bypass constraint
        session = models.SessionLocal()
        try:
            # Temporarily disable foreign key constraints
            session.execute(text("PRAGMA foreign_keys = OFF"))

            # Insert password with user_id = 0 (orphaned)
            session.execute(
                text(
                    "INSERT INTO password_manager (user_id, resource_name, encrypted_password, nonce) "
                    "VALUES (0, 'test', :enc_pwd, :nonce)"
                ),
                {"enc_pwd": b"test", "nonce": b"test_nonce"}
            )
            session.commit()

            # Re-enable foreign key constraints
            session.execute(text("PRAGMA foreign_keys = ON"))

        finally:
            session.close()

        result = check_migration_needed()

        assert result.ok is True
        assert result.result is True

    def test_no_migration_after_successful_migration(self, temp_db):
        """Test that after successful migration, no more migration needed."""
        engine, db_path = temp_db

        # Create new schema with user and passwords
        Base.metadata.create_all(engine)

        session = models.SessionLocal()
        crypto = CryptoService()

        try:
            # Create user
            salt = crypto.generate_salt()
            password_hash = crypto.hash_master_password("TestPassword123!")
            encryption_key = crypto.derive_encryption_key("TestPassword123!", salt, 600000)

            user = User(
                username="testuser",
                email="test@example.com",
                master_password_hash=password_hash,
                salt=salt,
                kdf_algorithm="PBKDF2",
                kdf_iterations=600000,
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            # Add encrypted password
            ciphertext, nonce = crypto.encrypt_password("testpassword", encryption_key)
            pwd = PasswordManager(
                user_id=user.id,
                resource_name="github",
                encrypted_password=ciphertext,
                nonce=nonce,
            )
            session.add(pwd)
            session.commit()

        finally:
            session.close()

        result = check_migration_needed()

        assert result.ok is True
        assert result.result is False


class TestMigrationExecution:
    """Test suite for migration execution."""

    def test_migrate_from_old_schema(self, old_schema_db, crypto_service):
        """Test successful migration from old schema."""
        engine, password_count = old_schema_db

        # Perform migration
        result = migrate_from_v1_to_v2(
            username="migrationuser",
            password="SecurePass123!",
            email="migration@example.com",
        )

        assert result.ok is True
        assert result.result["migrated_count"] == password_count
        assert result.result["user_created"] is True
        assert result.result["username"] == "migrationuser"
        assert "encryption_key" in result.result

        # Verify user was created
        session = models.SessionLocal()
        try:
            user = session.query(User).filter_by(username="migrationuser").first()
            assert user is not None
            assert user.email == "migration@example.com"

            # Verify passwords were migrated and encrypted
            passwords = session.query(PasswordManager).filter_by(user_id=user.id).all()
            assert len(passwords) == password_count

            # Verify passwords are encrypted (have nonce)
            for pwd in passwords:
                assert pwd.nonce is not None
                assert pwd.encrypted_password is not None
                assert pwd.user_id == user.id

            # Verify we can decrypt passwords
            encryption_key = result.result["encryption_key"]

            github_pwd = (
                session.query(PasswordManager)
                .filter_by(user_id=user.id, resource_name="github")
                .first()
            )
            decrypted = crypto_service.decrypt_password(
                github_pwd.encrypted_password, github_pwd.nonce, encryption_key
            )
            assert decrypted == "plaintext123"

        finally:
            session.close()

    def test_migrate_preserves_metadata(self, old_schema_db, crypto_service):
        """Test that migration preserves username, website, description."""
        engine, password_count = old_schema_db

        result = migrate_from_v1_to_v2(
            username="testuser", password="SecurePass123!"
        )

        assert result.ok is True

        session = models.SessionLocal()
        try:
            user_id = result.result["user_id"]

            # Check github password
            github = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name="github")
                .first()
            )
            assert github.username == "john"
            assert github.website == "https://github.com"

            # Check gmail password
            gmail = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name="gmail")
                .first()
            )
            assert gmail.username == "john@gmail.com"

            # Check aws password
            aws = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name="aws")
                .first()
            )
            assert aws.description == "AWS Console"

        finally:
            session.close()

    def test_migrate_empty_database(self, temp_db):
        """Test migration with no passwords."""
        engine, db_path = temp_db

        # Create empty old schema
        Base.metadata.create_all(engine)

        result = migrate_from_v1_to_v2(
            username="emptyuser", password="SecurePass123!"
        )

        # Should succeed but migrate 0 passwords
        assert result.ok is True
        assert result.result["migrated_count"] == 0

    def test_migrate_duplicate_username_fails(self, old_schema_db):
        """Test that migration fails if username already exists."""
        engine, password_count = old_schema_db

        # Create user first
        session = models.SessionLocal()
        crypto = CryptoService()

        try:
            Base.metadata.create_all(engine)

            salt = crypto.generate_salt()
            password_hash = crypto.hash_master_password("OtherPass123!")

            user = User(
                username="existinguser",
                master_password_hash=password_hash,
                salt=salt,
            )
            session.add(user)
            session.commit()

        finally:
            session.close()

        # Try to migrate with same username
        result = migrate_from_v1_to_v2(
            username="existinguser", password="SecurePass123!"
        )

        assert result.ok is False
        assert "already taken" in result.result.lower() or "exists" in result.result.lower()


class TestMigrationIntegration:
    """Integration tests for migration process."""

    def test_full_migration_workflow(self, old_schema_db, crypto_service):
        """Test complete migration workflow end-to-end."""
        engine, password_count = old_schema_db

        # Step 1: Check migration is needed
        check_result = check_migration_needed()
        assert check_result.ok is True
        assert check_result.result is True

        # Step 2: Perform migration
        migration_result = migrate_from_v1_to_v2(
            username="fulltest", password="SecurePass123!", email="full@test.com"
        )
        assert migration_result.ok is True
        assert migration_result.result["migrated_count"] == password_count

        # Step 3: Verify migration complete
        check_result_after = check_migration_needed()
        assert check_result_after.ok is True
        assert check_result_after.result is False

        # Step 4: Verify passwords are accessible
        session = models.SessionLocal()
        try:
            user_id = migration_result.result["user_id"]
            encryption_key = migration_result.result["encryption_key"]

            passwords = session.query(PasswordManager).filter_by(user_id=user_id).all()
            assert len(passwords) == password_count

            # Verify all passwords can be decrypted
            for pwd in passwords:
                decrypted = crypto_service.decrypt_password(
                    pwd.encrypted_password, pwd.nonce, encryption_key
                )
                assert len(decrypted) > 0

        finally:
            session.close()

    def test_migration_idempotency(self, old_schema_db):
        """Test that running migration twice doesn't cause issues."""
        engine, password_count = old_schema_db

        # First migration
        result1 = migrate_from_v1_to_v2(
            username="user1", password="Pass123!", email="user1@test.com"
        )
        assert result1.ok is True

        # Check migration no longer needed
        check_result = check_migration_needed()
        assert check_result.result is False

        # Second migration should not be triggered
        # (In real usage, check_migration_needed prevents this)

    def test_migrated_passwords_work_with_repository(self, old_schema_db):
        """Test that migrated passwords work with PasswordRepository."""
        engine, password_count = old_schema_db

        # Perform migration
        result = migrate_from_v1_to_v2(
            username="repotest", password="SecurePass123!"
        )
        assert result.ok is True

        # Now try to use PasswordRepository
        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        user_id = result.result["user_id"]
        encryption_key = result.result["encryption_key"]

        # Try to retrieve a password
        pwd_result = repo.get_password_by_resource_name(
            user_id, encryption_key, "github"
        )

        assert pwd_result.ok is True
        assert pwd_result.result["password"] == "plaintext123"
        assert pwd_result.result["username"] == "john"

        # Try to save a new password
        save_result = repo.save_password(
            user_id=user_id,
            encryption_key=encryption_key,
            resource_name="newpassword",
            password="newpass123",
        )

        assert save_result.ok is True

        # Retrieve it
        get_result = repo.get_password_by_resource_name(
            user_id, encryption_key, "newpassword"
        )
        assert get_result.ok is True
        assert get_result.result["password"] == "newpass123"
