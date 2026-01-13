"""Unit tests for database models.

Tests User and PasswordManager models including:
- Model creation and constraints
- Relationships
- Database operations
"""

import os
import tempfile
from datetime import datetime

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from passwault.core.database.models import Base, User, PasswordManager
from passwault.core.services.crypto_service import CryptoService


@pytest.fixture
def test_db():
    """Create a temporary test database."""
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")

    # Create engine and tables
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)

    # Create session factory
    TestSession = sessionmaker(bind=engine)

    yield TestSession, engine

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def crypto_service():
    """Provide CryptoService instance."""
    return CryptoService()


class TestUserModel:
    """Test suite for User model."""

    def test_create_user(self, test_db, crypto_service):
        """Test creating a user with all required fields."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            salt = crypto_service.generate_salt()
            password_hash = crypto_service.hash_master_password("TestPassword123!")

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

            assert user.id is not None
            assert user.username == "testuser"
            assert user.email == "test@example.com"
            assert user.master_password_hash == password_hash
            assert user.salt == salt
            assert user.kdf_algorithm == "PBKDF2"
            assert user.kdf_iterations == 600000
            assert user.created_at is not None
            assert user.updated_at is not None
            assert user.last_login is None

        finally:
            session.close()

    def test_create_user_without_email(self, test_db, crypto_service):
        """Test creating a user without email (optional field)."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            salt = crypto_service.generate_salt()
            password_hash = crypto_service.hash_master_password("TestPassword123!")

            user = User(
                username="testuser",
                master_password_hash=password_hash,
                salt=salt,
            )

            session.add(user)
            session.commit()

            assert user.email is None

        finally:
            session.close()

    def test_username_unique_constraint(self, test_db, crypto_service):
        """Test that username must be unique."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            salt1 = crypto_service.generate_salt()
            salt2 = crypto_service.generate_salt()
            hash1 = crypto_service.hash_master_password("Pass1")
            hash2 = crypto_service.hash_master_password("Pass2")

            # Create first user
            user1 = User(
                username="testuser",
                master_password_hash=hash1,
                salt=salt1,
            )
            session.add(user1)
            session.commit()

            # Try to create second user with same username
            user2 = User(
                username="testuser",
                master_password_hash=hash2,
                salt=salt2,
            )
            session.add(user2)

            with pytest.raises(IntegrityError):
                session.commit()

        finally:
            session.rollback()
            session.close()

    def test_email_unique_constraint(self, test_db, crypto_service):
        """Test that email must be unique."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            salt1 = crypto_service.generate_salt()
            salt2 = crypto_service.generate_salt()
            hash1 = crypto_service.hash_master_password("Pass1")
            hash2 = crypto_service.hash_master_password("Pass2")

            # Create first user
            user1 = User(
                username="user1",
                email="test@example.com",
                master_password_hash=hash1,
                salt=salt1,
            )
            session.add(user1)
            session.commit()

            # Try to create second user with same email
            user2 = User(
                username="user2",
                email="test@example.com",
                master_password_hash=hash2,
                salt=salt2,
            )
            session.add(user2)

            with pytest.raises(IntegrityError):
                session.commit()

        finally:
            session.rollback()
            session.close()

    def test_user_repr(self, test_db, crypto_service):
        """Test User __repr__ method."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            repr_str = repr(user)
            assert "User" in repr_str
            assert str(user.id) in repr_str
            assert "testuser" in repr_str

        finally:
            session.close()

    def test_user_default_values(self, test_db, crypto_service):
        """Test User model default values."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            assert user.kdf_algorithm == "PBKDF2"
            assert user.kdf_iterations == 600000

        finally:
            session.close()


class TestPasswordManagerModel:
    """Test suite for PasswordManager model."""

    def test_create_password_entry(self, test_db, crypto_service):
        """Test creating a password entry."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create user first
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            # Encrypt password
            encryption_key = crypto_service.generate_salt(length=32)
            ciphertext, nonce = crypto_service.encrypt_password(
                "MyPassword123", encryption_key
            )

            # Create password entry
            password_entry = PasswordManager(
                user_id=user.id,
                resource_name="github",
                username="myusername",
                encrypted_password=ciphertext,
                nonce=nonce,
                website="https://github.com",
                description="My GitHub account",
                tags="work,development",
            )

            session.add(password_entry)
            session.commit()
            session.refresh(password_entry)

            assert password_entry.id is not None
            assert password_entry.user_id == user.id
            assert password_entry.resource_name == "github"
            assert password_entry.username == "myusername"
            assert password_entry.encrypted_password == ciphertext
            assert password_entry.nonce == nonce
            assert password_entry.website == "https://github.com"
            assert password_entry.description == "My GitHub account"
            assert password_entry.tags == "work,development"
            assert password_entry.created_at is not None
            assert password_entry.updated_at is not None

        finally:
            session.close()

    def test_password_entry_minimal_fields(self, test_db, crypto_service):
        """Test creating password entry with only required fields."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create user
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            # Create password entry with minimal fields
            encryption_key = crypto_service.generate_salt(length=32)
            ciphertext, nonce = crypto_service.encrypt_password("pass", encryption_key)

            password_entry = PasswordManager(
                user_id=user.id,
                resource_name="test",
                encrypted_password=ciphertext,
                nonce=nonce,
            )

            session.add(password_entry)
            session.commit()

            assert password_entry.username is None
            assert password_entry.website is None
            assert password_entry.description is None
            assert password_entry.tags is None

        finally:
            session.close()

    def test_unique_user_resource_constraint(self, test_db, crypto_service):
        """Test that user_id + resource_name must be unique."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create user
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            # Create first password entry
            encryption_key = crypto_service.generate_salt(length=32)
            cipher1, nonce1 = crypto_service.encrypt_password("pass1", encryption_key)

            entry1 = PasswordManager(
                user_id=user.id,
                resource_name="github",
                encrypted_password=cipher1,
                nonce=nonce1,
            )
            session.add(entry1)
            session.commit()

            # Try to create duplicate
            cipher2, nonce2 = crypto_service.encrypt_password("pass2", encryption_key)
            entry2 = PasswordManager(
                user_id=user.id,
                resource_name="github",  # Same resource name
                encrypted_password=cipher2,
                nonce=nonce2,
            )
            session.add(entry2)

            with pytest.raises(IntegrityError):
                session.commit()

        finally:
            session.rollback()
            session.close()

    def test_different_users_same_resource(self, test_db, crypto_service):
        """Test that different users can have same resource name."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create two users
            user1 = User(
                username="user1",
                master_password_hash=crypto_service.hash_master_password("pass1"),
                salt=crypto_service.generate_salt(),
            )
            user2 = User(
                username="user2",
                master_password_hash=crypto_service.hash_master_password("pass2"),
                salt=crypto_service.generate_salt(),
            )
            session.add_all([user1, user2])
            session.commit()

            # Both users create password for "github"
            encryption_key = crypto_service.generate_salt(length=32)
            cipher1, nonce1 = crypto_service.encrypt_password("pass1", encryption_key)
            cipher2, nonce2 = crypto_service.encrypt_password("pass2", encryption_key)

            entry1 = PasswordManager(
                user_id=user1.id,
                resource_name="github",
                encrypted_password=cipher1,
                nonce=nonce1,
            )
            entry2 = PasswordManager(
                user_id=user2.id,
                resource_name="github",
                encrypted_password=cipher2,
                nonce=nonce2,
            )

            session.add_all([entry1, entry2])
            session.commit()  # Should succeed

            # Verify both entries exist
            assert entry1.id is not None
            assert entry2.id is not None
            assert entry1.id != entry2.id

        finally:
            session.close()

    def test_password_repr(self, test_db, crypto_service):
        """Test PasswordManager __repr__ method."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            encryption_key = crypto_service.generate_salt(length=32)
            cipher, nonce = crypto_service.encrypt_password("pass", encryption_key)

            entry = PasswordManager(
                user_id=user.id,
                resource_name="github",
                encrypted_password=cipher,
                nonce=nonce,
            )
            session.add(entry)
            session.commit()
            session.refresh(entry)

            repr_str = repr(entry)
            assert "PasswordManager" in repr_str
            assert str(entry.id) in repr_str
            assert str(entry.user_id) in repr_str
            assert "github" in repr_str

        finally:
            session.close()


class TestUserPasswordRelationship:
    """Test suite for User-PasswordManager relationship."""

    def test_user_passwords_relationship(self, test_db, crypto_service):
        """Test that user can access their passwords through relationship."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create user
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            # Create multiple password entries
            encryption_key = crypto_service.generate_salt(length=32)

            for resource in ["github", "gitlab", "bitbucket"]:
                cipher, nonce = crypto_service.encrypt_password(
                    f"pass_{resource}", encryption_key
                )
                entry = PasswordManager(
                    user_id=user.id,
                    resource_name=resource,
                    encrypted_password=cipher,
                    nonce=nonce,
                )
                session.add(entry)

            session.commit()
            session.refresh(user)

            # Access passwords through relationship
            assert len(user.passwords) == 3
            resource_names = [p.resource_name for p in user.passwords]
            assert "github" in resource_names
            assert "gitlab" in resource_names
            assert "bitbucket" in resource_names

        finally:
            session.close()

    def test_cascade_delete_user(self, test_db, crypto_service):
        """Test that deleting user cascades to delete passwords."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            # Create user with passwords
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            encryption_key = crypto_service.generate_salt(length=32)
            cipher, nonce = crypto_service.encrypt_password("pass", encryption_key)

            entry = PasswordManager(
                user_id=user.id,
                resource_name="github",
                encrypted_password=cipher,
                nonce=nonce,
            )
            session.add(entry)
            session.commit()

            user_id = user.id
            entry_id = entry.id

            # Delete user
            session.delete(user)
            session.commit()

            # Verify password was deleted too
            deleted_entry = (
                session.query(PasswordManager).filter_by(id=entry_id).first()
            )
            assert deleted_entry is None

        finally:
            session.close()

    def test_password_user_relationship(self, test_db, crypto_service):
        """Test that password entry can access its user."""
        SessionLocal, _ = test_db
        session = SessionLocal()

        try:
            user = User(
                username="testuser",
                master_password_hash=crypto_service.hash_master_password("pass"),
                salt=crypto_service.generate_salt(),
            )
            session.add(user)
            session.commit()

            encryption_key = crypto_service.generate_salt(length=32)
            cipher, nonce = crypto_service.encrypt_password("pass", encryption_key)

            entry = PasswordManager(
                user_id=user.id,
                resource_name="github",
                encrypted_password=cipher,
                nonce=nonce,
            )
            session.add(entry)
            session.commit()
            session.refresh(entry)

            # Access user through relationship
            assert entry.user is not None
            assert entry.user.username == "testuser"
            assert entry.user.id == user.id

        finally:
            session.close()


class TestDatabaseIndexes:
    """Test that indexes are created correctly."""

    def test_indexes_exist(self, test_db):
        """Test that expected indexes exist on tables."""
        _, engine = test_db
        inspector = inspect(engine)

        # Check PasswordManager indexes
        pm_indexes = inspector.get_indexes("password_manager")
        index_names = [idx["name"] for idx in pm_indexes]

        assert "idx_user_passwords" in index_names
        assert "idx_resource_name" in index_names

        # Check User indexes (username should be indexed due to unique constraint)
        user_indexes = inspector.get_indexes("users")
        # SQLite creates indexes automatically for UNIQUE constraints
