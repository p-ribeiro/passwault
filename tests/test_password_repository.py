"""Unit tests for PasswordRepository.

Tests encrypted password storage, retrieval, updates, and deletion
with multi-user isolation.
"""

import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passwault.core.database.models import Base, User, PasswordManager
from passwault.core.database.password_manager import PasswordRepository
from passwault.core.services.crypto_service import CryptoService


@pytest.fixture
def test_db():
    """Create a temporary test database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")

    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)

    from passwault.core.database import models

    original_session = models.SessionLocal
    models.SessionLocal = sessionmaker(bind=engine)

    yield engine

    models.SessionLocal = original_session
    Base.metadata.drop_all(engine)
    engine.dispose()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def password_repo():
    """Provide PasswordRepository instance."""
    return PasswordRepository()


@pytest.fixture
def crypto_service():
    """Provide CryptoService instance."""
    return CryptoService()


@pytest.fixture
def test_user(test_db, crypto_service):
    """Create a test user with encryption key."""
    from passwault.core.database.models import SessionLocal

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

        # Derive encryption key
        encryption_key = crypto_service.derive_encryption_key(
            "TestPassword123!", salt, 600000
        )

        yield {"user_id": user.id, "encryption_key": encryption_key}

    finally:
        session.close()


class TestPasswordSave:
    """Test suite for saving passwords."""

    def test_save_password_success(self, test_db, password_repo, test_user):
        """Test successful password save with encryption."""
        result = password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="github",
            password="mypassword123",
            username="john",
            website="https://github.com",
            description="My GitHub account",
            tags="work,development",
        )

        assert result.ok is True
        assert isinstance(result.result, int)
        assert result.result > 0

    def test_save_password_minimal_fields(self, test_db, password_repo, test_user):
        """Test saving password with only required fields."""
        result = password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="gitlab",
            password="password123",
        )

        assert result.ok is True

    def test_save_password_duplicate_resource(self, test_db, password_repo, test_user):
        """Test that duplicate resource names are rejected."""
        # Save first password
        password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="github",
            password="password1",
        )

        # Try to save with same resource name
        result = password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="github",
            password="password2",
        )

        assert result.ok is False
        assert "already exists" in result.result.lower()

    def test_save_password_encrypts_data(
        self, test_db, password_repo, test_user, crypto_service
    ):
        """Test that password is encrypted in database."""
        plaintext_password = "mypassword123"

        result = password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="github",
            password=plaintext_password,
        )

        assert result.ok is True

        # Query database directly
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            entry = session.query(PasswordManager).filter_by(id=result.result).first()

            # Encrypted password should not equal plaintext
            assert entry.encrypted_password != plaintext_password.encode()

            # But should decrypt correctly
            decrypted = crypto_service.decrypt_password(
                entry.encrypted_password,
                entry.nonce,
                test_user["encryption_key"],
            )
            assert decrypted == plaintext_password

        finally:
            session.close()


class TestPasswordRetrieval:
    """Test suite for retrieving passwords."""

    def test_get_password_by_resource_name(self, test_db, password_repo, test_user):
        """Test retrieving password by resource name."""
        # Save password
        password_repo.save_password(
            user_id=test_user["user_id"],
            encryption_key=test_user["encryption_key"],
            resource_name="github",
            password="mypassword123",
            username="john",
        )

        # Retrieve password
        result = password_repo.get_password_by_resource_name(
            test_user["user_id"], test_user["encryption_key"], "github"
        )

        assert result.ok is True
        assert result.result["resource_name"] == "github"
        assert result.result["password"] == "mypassword123"
        assert result.result["username"] == "john"

    def test_get_password_not_found(self, test_db, password_repo, test_user):
        """Test retrieving non-existent password."""
        result = password_repo.get_password_by_resource_name(
            test_user["user_id"], test_user["encryption_key"], "nonexistent"
        )

        assert result.ok is False
        assert "no password found" in result.result.lower()

    def test_get_password_by_username(self, test_db, password_repo, test_user):
        """Test retrieving passwords by username."""
        # Save multiple passwords with same username
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "pass1",
            username="john",
        )
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "gitlab",
            "pass2",
            username="john",
        )

        result = password_repo.get_password_by_username(
            test_user["user_id"], test_user["encryption_key"], "john"
        )

        assert result.ok is True
        assert len(result.result) == 2
        assert result.result[0]["username"] == "john"
        assert result.result[1]["username"] == "john"

    def test_get_all_passwords(self, test_db, password_repo, test_user):
        """Test retrieving all passwords for a user."""
        # Save multiple passwords
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "pass1",
        )
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "gitlab",
            "pass2",
        )
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "bitbucket",
            "pass3",
        )

        result = password_repo.get_all_passwords(
            test_user["user_id"], test_user["encryption_key"]
        )

        assert result.ok is True
        assert len(result.result) == 3

    def test_get_all_passwords_empty(self, test_db, password_repo, test_user):
        """Test retrieving all passwords when none exist."""
        result = password_repo.get_all_passwords(
            test_user["user_id"], test_user["encryption_key"]
        )

        assert result.ok is False
        assert "no passwords found" in result.result.lower()

    def test_decryption_with_wrong_key(
        self, test_db, password_repo, test_user, crypto_service
    ):
        """Test that decryption fails with wrong key."""
        # Save password
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "mypassword123",
        )

        # Try to retrieve with wrong key
        wrong_key = crypto_service.generate_salt(length=32)
        result = password_repo.get_password_by_resource_name(
            test_user["user_id"], wrong_key, "github"
        )

        assert result.ok is False
        assert "decrypt" in result.result.lower()


class TestPasswordUpdate:
    """Test suite for updating passwords."""

    def test_update_password_success(self, test_db, password_repo, test_user):
        """Test successful password update."""
        # Save initial password
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "oldpassword",
        )

        # Update password
        result = password_repo.update_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "newpassword",
        )

        assert result.ok is True

        # Verify new password
        get_result = password_repo.get_password_by_resource_name(
            test_user["user_id"], test_user["encryption_key"], "github"
        )
        assert get_result.result["password"] == "newpassword"

    def test_update_password_with_metadata(self, test_db, password_repo, test_user):
        """Test updating password with additional metadata."""
        # Save initial password
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "oldpassword",
        )

        # Update password and metadata
        result = password_repo.update_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "newpassword",
            username="newuser",
            website="https://github.com/new",
            description="Updated",
            tags="new,tags",
        )

        assert result.ok is True

        # Verify updates
        get_result = password_repo.get_password_by_resource_name(
            test_user["user_id"], test_user["encryption_key"], "github"
        )
        assert get_result.result["password"] == "newpassword"
        assert get_result.result["username"] == "newuser"
        assert get_result.result["website"] == "https://github.com/new"

    def test_update_nonexistent_password(self, test_db, password_repo, test_user):
        """Test updating non-existent password."""
        result = password_repo.update_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "nonexistent",
            "newpassword",
        )

        assert result.ok is False
        assert "no password found" in result.result.lower()


class TestPasswordDelete:
    """Test suite for deleting passwords."""

    def test_delete_password_success(self, test_db, password_repo, test_user):
        """Test successful password deletion."""
        # Save password
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "password123",
        )

        # Delete password
        result = password_repo.delete_password(test_user["user_id"], "github")

        assert result.ok is True

        # Verify deletion
        get_result = password_repo.get_password_by_resource_name(
            test_user["user_id"], test_user["encryption_key"], "github"
        )
        assert get_result.ok is False

    def test_delete_nonexistent_password(self, test_db, password_repo, test_user):
        """Test deleting non-existent password."""
        result = password_repo.delete_password(test_user["user_id"], "nonexistent")

        assert result.ok is False
        assert "no password found" in result.result.lower()


class TestResourceCheck:
    """Test suite for checking resource existence."""

    def test_check_resource_exists_true(self, test_db, password_repo, test_user):
        """Test checking existing resource."""
        password_repo.save_password(
            test_user["user_id"],
            test_user["encryption_key"],
            "github",
            "password123",
        )

        result = password_repo.check_resource_exists(test_user["user_id"], "github")

        assert result.ok is True
        assert result.result is True

    def test_check_resource_exists_false(self, test_db, password_repo, test_user):
        """Test checking non-existent resource."""
        result = password_repo.check_resource_exists(
            test_user["user_id"], "nonexistent"
        )

        assert result.ok is True
        assert result.result is False


class TestMultiUserIsolation:
    """Test suite for multi-user data isolation."""

    def test_different_users_different_passwords(
        self, test_db, password_repo, crypto_service
    ):
        """Test that different users have isolated password storage."""
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            # Create two users
            salt1 = crypto_service.generate_salt()
            salt2 = crypto_service.generate_salt()

            user1 = User(
                username="user1",
                master_password_hash=crypto_service.hash_master_password("pass1"),
                salt=salt1,
            )
            user2 = User(
                username="user2",
                master_password_hash=crypto_service.hash_master_password("pass2"),
                salt=salt2,
            )

            session.add_all([user1, user2])
            session.commit()
            session.refresh(user1)
            session.refresh(user2)

            key1 = crypto_service.derive_encryption_key("pass1", salt1, 600000)
            key2 = crypto_service.derive_encryption_key("pass2", salt2, 600000)

        finally:
            session.close()

        # User 1 saves password
        password_repo.save_password(user1.id, key1, "github", "user1password")

        # User 2 cannot see user 1's password
        result = password_repo.get_password_by_resource_name(user2.id, key2, "github")
        assert result.ok is False

        # User 2 can save their own password with same resource name
        result = password_repo.save_password(user2.id, key2, "github", "user2password")
        assert result.ok is True

        # Each user can only access their own password
        user1_result = password_repo.get_password_by_resource_name(
            user1.id, key1, "github"
        )
        user2_result = password_repo.get_password_by_resource_name(
            user2.id, key2, "github"
        )

        assert user1_result.result["password"] == "user1password"
        assert user2_result.result["password"] == "user2password"

    def test_user_cannot_decrypt_other_users_passwords(
        self, test_db, password_repo, crypto_service
    ):
        """Test that users cannot decrypt other users' passwords."""
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            # Create two users
            salt1 = crypto_service.generate_salt()
            salt2 = crypto_service.generate_salt()

            user1 = User(
                username="user1",
                master_password_hash=crypto_service.hash_master_password("pass1"),
                salt=salt1,
            )
            user2 = User(
                username="user2",
                master_password_hash=crypto_service.hash_master_password("pass2"),
                salt=salt2,
            )

            session.add_all([user1, user2])
            session.commit()
            session.refresh(user1)
            session.refresh(user2)

            key1 = crypto_service.derive_encryption_key("pass1", salt1, 600000)
            key2 = crypto_service.derive_encryption_key("pass2", salt2, 600000)

        finally:
            session.close()

        # User 1 saves password
        password_repo.save_password(user1.id, key1, "github", "secretpassword")

        # Get entry from database
        session = SessionLocal()
        try:
            entry = (
                session.query(PasswordManager)
                .filter_by(user_id=user1.id, resource_name="github")
                .first()
            )

            # Try to decrypt with user2's key
            from cryptography.exceptions import InvalidTag

            with pytest.raises(InvalidTag):
                crypto_service.decrypt_password(
                    entry.encrypted_password, entry.nonce, key2
                )

        finally:
            session.close()
