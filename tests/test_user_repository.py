"""Unit tests for UserRepository.

Tests user registration, authentication, and user management operations.
"""

import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passwault.core.database.models import Base, User
from passwault.core.database.user_repository import UserRepository
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.local_types import (
    AuthenticationError,
    ResourceExistsError,
    ResourceNotFoundError,
)


@pytest.fixture
def test_db():
    """Create a temporary test database."""
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")

    # Create engine and tables
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)

    # Replace SessionLocal temporarily
    from passwault.core.database import models

    original_session = models.SessionLocal
    models.SessionLocal = sessionmaker(bind=engine)

    yield engine

    # Restore original SessionLocal
    models.SessionLocal = original_session

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def user_repo():
    """Provide UserRepository instance."""
    return UserRepository()


@pytest.fixture
def crypto_service():
    """Provide CryptoService instance."""
    return CryptoService()


class TestUserRegistration:
    """Test suite for user registration."""

    def test_register_user_success(self, test_db, user_repo):
        """Test successful user registration."""
        user_id = user_repo.register("testuser", "SecurePassword123!")

        assert isinstance(user_id, int)  # User ID
        assert user_id > 0

    def test_register_user_with_email(self, test_db, user_repo):
        """Test user registration with email."""
        user_id = user_repo.register(
            "testuser", "SecurePassword123!", email="test@example.com"
        )

        # Verify user was created with email
        user_data = user_repo.get_user_by_id(user_id)
        assert user_data["email"] == "test@example.com"

    def test_register_duplicate_username(self, test_db, user_repo):
        """Test that registering duplicate username fails."""
        # Register first user
        user_repo.register("testuser", "Password1")

        # Try to register with same username
        with pytest.raises(ResourceExistsError, match="already exists"):
            user_repo.register("testuser", "Password2")

    def test_register_duplicate_email(self, test_db, user_repo):
        """Test that registering duplicate email fails."""
        # Register first user
        user_repo.register("user1", "Password1", email="test@example.com")

        # Try to register with same email
        with pytest.raises(ResourceExistsError, match="already exists"):
            user_repo.register("user2", "Password2", email="test@example.com")

    def test_register_stores_hashed_password(self, test_db, user_repo, crypto_service):
        """Test that password is stored hashed, not plaintext."""
        password = "SecurePassword123!"
        user_repo.register("testuser", password)

        # Query user directly from database
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is not None

            # Password hash should not be the plaintext password
            assert user.master_password_hash != password.encode()

            # But it should verify correctly
            assert crypto_service.verify_master_password(
                password, user.master_password_hash
            )

        finally:
            session.close()

    def test_register_generates_unique_salt(self, test_db, user_repo):
        """Test that each user gets a unique salt."""
        user_repo.register("user1", "Password1")
        user_repo.register("user2", "Password2")

        # Query users directly
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user1 = session.query(User).filter_by(username="user1").first()
            user2 = session.query(User).filter_by(username="user2").first()

            assert user1.salt != user2.salt

        finally:
            session.close()

    def test_register_sets_kdf_parameters(self, test_db, user_repo):
        """Test that KDF parameters are set correctly."""
        user_repo.register("testuser", "Password123")

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()

            assert user.kdf_algorithm == "PBKDF2"
            assert user.kdf_iterations == 600000

        finally:
            session.close()


class TestUserAuthentication:
    """Test suite for user authentication."""

    def test_authenticate_success(self, test_db, user_repo):
        """Test successful authentication."""
        # Register user
        username = "testuser"
        password = "SecurePassword123!"
        user_repo.register(username, password)

        # Authenticate
        auth_data = user_repo.authenticate(username, password)
        assert "user_id" in auth_data
        assert "username" in auth_data
        assert "encryption_key" in auth_data
        assert auth_data["username"] == username

    def test_authenticate_wrong_password(self, test_db, user_repo):
        """Test authentication with wrong password."""
        username = "testuser"
        password = "CorrectPassword"

        user_repo.register(username, password)

        # Try with wrong password
        with pytest.raises(AuthenticationError, match="Invalid password"):
            user_repo.authenticate(username, "WrongPassword")

    def test_authenticate_nonexistent_user(self, test_db, user_repo):
        """Test authentication with non-existent user."""
        with pytest.raises(AuthenticationError, match="User not found"):
            user_repo.authenticate("nonexistent", "password")

    def test_authenticate_case_sensitive(self, test_db, user_repo):
        """Test that authentication is case-sensitive."""
        user_repo.register("TestUser", "Password123")

        # Try with different case
        with pytest.raises((ResourceNotFoundError, AuthenticationError)):
            user_repo.authenticate("testuser", "Password123")

    def test_authenticate_returns_encryption_key(self, test_db, user_repo):
        """Test that authentication returns encryption key."""
        username = "testuser"
        password = "Password123"

        user_repo.register(username, password)
        auth_data = user_repo.authenticate(username, password)

        encryption_key = auth_data["encryption_key"]

        assert isinstance(encryption_key, bytes)
        assert len(encryption_key) == 32  # 256 bits

    def test_authenticate_encryption_key_deterministic(self, test_db, user_repo):
        """Test that same credentials produce same encryption key."""
        username = "testuser"
        password = "Password123"

        user_repo.register(username, password)

        # Authenticate twice
        auth1 = user_repo.authenticate(username, password)
        auth2 = user_repo.authenticate(username, password)

        key1 = auth1["encryption_key"]
        key2 = auth2["encryption_key"]

        assert key1 == key2

    def test_authenticate_different_users_different_keys(self, test_db, user_repo):
        """Test that different users have different encryption keys."""
        password = "SamePassword123"

        user_repo.register("user1", password)
        user_repo.register("user2", password)

        auth1 = user_repo.authenticate("user1", password)
        auth2 = user_repo.authenticate("user2", password)

        key1 = auth1["encryption_key"]
        key2 = auth2["encryption_key"]

        assert key1 != key2  # Different salts produce different keys

    def test_authenticate_updates_last_login(self, test_db, user_repo):
        """Test that authentication updates last_login timestamp."""
        username = "testuser"
        password = "Password123"

        user_repo.register(username, password)

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            # Check last_login is None initially
            user = session.query(User).filter_by(username=username).first()
            assert user.last_login is None

            # Authenticate
            user_repo.authenticate(username, password)

            # Refresh user from database
            session.expire(user)
            session.refresh(user)

            # last_login should now be set
            assert user.last_login is not None

        finally:
            session.close()


class TestUserRetrieval:
    """Test suite for user retrieval operations."""

    def test_get_user_by_id(self, test_db, user_repo):
        """Test retrieving user by ID."""
        user_id = user_repo.register(
            "testuser", "Password123", email="test@example.com"
        )

        user_data = user_repo.get_user_by_id(user_id)

        assert user_data["user_id"] == user_id
        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"
        assert "created_at" in user_data

        # Sensitive data should not be included
        assert "master_password_hash" not in user_data
        assert "salt" not in user_data

    def test_get_user_by_id_not_found(self, test_db, user_repo):
        """Test retrieving non-existent user by ID."""
        with pytest.raises(ResourceNotFoundError, match="not found"):
            user_repo.get_user_by_id(99999)

    def test_get_user_by_username(self, test_db, user_repo):
        """Test retrieving user by username."""
        user_repo.register("testuser", "Password123", email="test@example.com")

        user_data = user_repo.get_user_by_username("testuser")

        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"

    def test_get_user_by_username_not_found(self, test_db, user_repo):
        """Test retrieving non-existent user by username."""
        with pytest.raises(ResourceNotFoundError, match="not found"):
            user_repo.get_user_by_username("nonexistent")

    def test_check_username_exists_true(self, test_db, user_repo):
        """Test checking if username exists (positive case)."""
        user_repo.register("testuser", "Password123")

        exists = user_repo.check_username_exists("testuser")

        assert exists is True

    def test_check_username_exists_false(self, test_db, user_repo):
        """Test checking if username exists (negative case)."""
        exists = user_repo.check_username_exists("nonexistent")

        assert exists is False


class TestUserRepositoryIntegration:
    """Integration tests for UserRepository."""

    def test_full_user_lifecycle(self, test_db, user_repo, crypto_service):
        """Test complete user lifecycle: register -> authenticate -> retrieve."""
        username = "testuser"
        password = "SecurePassword123!"
        email = "test@example.com"

        # Step 1: Register
        user_id = user_repo.register(username, password, email)

        # Step 2: Authenticate
        auth_data = user_repo.authenticate(username, password)
        assert auth_data["user_id"] == user_id

        encryption_key = auth_data["encryption_key"]

        # Step 3: Retrieve user info
        user_data = user_repo.get_user_by_id(user_id)
        assert user_data["username"] == username
        assert user_data["email"] == email

        # Step 4: Verify encryption key works
        test_password = "TestPassword123"
        ciphertext, nonce = crypto_service.encrypt_password(
            test_password, encryption_key
        )
        decrypted = crypto_service.decrypt_password(ciphertext, nonce, encryption_key)
        assert decrypted == test_password

    def test_multiple_users_isolation(self, test_db, user_repo, crypto_service):
        """Test that multiple users have isolated encryption."""
        # Create two users
        user_repo.register("user1", "Password1")
        user_repo.register("user2", "Password2")

        # Authenticate both
        auth1 = user_repo.authenticate("user1", "Password1")
        auth2 = user_repo.authenticate("user2", "Password2")

        key1 = auth1["encryption_key"]
        key2 = auth2["encryption_key"]

        # Keys should be different
        assert key1 != key2

        # Encrypt password with user1's key
        test_password = "SharedPassword"
        ciphertext, nonce = crypto_service.encrypt_password(test_password, key1)

        # User1 can decrypt
        decrypted1 = crypto_service.decrypt_password(ciphertext, nonce, key1)
        assert decrypted1 == test_password

        # User2 cannot decrypt (wrong key)
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            crypto_service.decrypt_password(ciphertext, nonce, key2)

    def test_authentication_after_multiple_registrations(self, test_db, user_repo):
        """Test authentication works correctly with multiple users registered."""
        users = [
            ("user1", "Password1"),
            ("user2", "Password2"),
            ("user3", "Password3"),
        ]

        # Register all users
        for username, password in users:
            user_repo.register(username, password)

        # Authenticate each user
        for username, password in users:
            auth_data = user_repo.authenticate(username, password)
            assert auth_data["username"] == username

    def test_username_check_before_registration(self, test_db, user_repo):
        """Test checking username availability before registration."""
        username = "testuser"

        # Check before registration
        exists_before = user_repo.check_username_exists(username)
        assert exists_before is False

        # Register
        user_repo.register(username, "Password123")

        # Check after registration
        exists_after = user_repo.check_username_exists(username)
        assert exists_after is True
