"""Unit tests for password management commands.

Tests save, load, update, delete, and generate password commands
with authentication requirements.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passwault.core.commands.password import (
    save_password,
    load_password,
    update_password,
    delete_password,
    generate_password,
)
from passwault.core.database.models import Base
from passwault.core.database.user_repository import UserRepository
from passwault.core.utils.session_manager import SessionManager


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
def temp_session_dir():
    """Create temporary directory for session files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def session_manager(temp_session_dir):
    """Create SessionManager with temporary directory."""

    def _init_with_temp(self, sf=".session"):
        self.root_path = temp_session_dir
        self.session_file_path = self.root_path / sf
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()
        self._encryption_key_cache = None

    with patch.object(SessionManager, "__init__", _init_with_temp):
        manager = SessionManager()
        yield manager


@pytest.fixture
def authenticated_user(test_db, session_manager):
    """Create and authenticate a test user."""
    user_repo = UserRepository()

    # Register user
    user_id = user_repo.register("testuser", "SecurePass123!", "test@example.com")
    assert user_id is not None

    # Authenticate and create session
    user_data = user_repo.authenticate("testuser", "SecurePass123!")
    assert user_data is not None

    session_manager.create_session(user_data)

    yield session_manager


class TestSavePasswordCommand:
    """Test suite for save_password command."""

    def test_save_password_requires_auth(self, test_db, session_manager):
        """Test that save_password requires authentication."""
        result = save_password("github", "password123", session_manager=session_manager)

        # Should return None when not authenticated
        assert result is None

    def test_save_password_success(self, test_db, authenticated_user):
        """Test successful password save."""
        save_password(
            "github",
            "mypassword123",
            username="john",
            website="https://github.com",
            session_manager=authenticated_user,
        )

        # Verify password was saved
        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        password_data = repo.get_password_by_resource_name(
            authenticated_user.get_user_id(),
            authenticated_user.get_encryption_key(),
            "github",
        )

        assert password_data is not None
        assert password_data["password"] == "mypassword123"

    def test_save_password_minimal_fields(self, test_db, authenticated_user):
        """Test saving password with minimal fields."""
        save_password("gitlab", "password123", session_manager=authenticated_user)

        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        password_data = repo.get_password_by_resource_name(
            authenticated_user.get_user_id(),
            authenticated_user.get_encryption_key(),
            "gitlab",
        )

        assert password_data is not None


class TestLoadPasswordCommand:
    """Test suite for load_password command."""

    def test_load_password_requires_auth(self, test_db, session_manager):
        """Test that load_password requires authentication."""
        result = load_password(resource_name="github", session_manager=session_manager)

        assert result is None

    def test_load_password_by_resource_name(self, test_db, authenticated_user):
        """Test loading password by resource name."""
        # Save password first
        save_password("github", "password123", session_manager=authenticated_user)

        # Load password
        load_password(resource_name="github", session_manager=authenticated_user)

    def test_load_password_not_found(self, test_db, authenticated_user):
        """Test loading non-existent password."""
        load_password(resource_name="nonexistent", session_manager=authenticated_user)

    def test_load_all_passwords(self, test_db, authenticated_user):
        """Test loading all passwords."""
        # Save multiple passwords
        save_password("github", "pass1", session_manager=authenticated_user)
        save_password("gitlab", "pass2", session_manager=authenticated_user)

        # Load all
        load_password(all_passwords=True, session_manager=authenticated_user)

    def test_load_all_passwords_empty(self, test_db, authenticated_user):
        """Test loading all passwords when none exist."""
        load_password(all_passwords=True, session_manager=authenticated_user)

    def test_load_password_by_username(self, test_db, authenticated_user):
        """Test loading passwords by username."""
        # Save passwords with same username
        save_password(
            "github", "pass1", username="john", session_manager=authenticated_user
        )
        save_password(
            "gitlab", "pass2", username="john", session_manager=authenticated_user
        )

        # Load by username
        load_password(username="john", session_manager=authenticated_user)


class TestUpdatePasswordCommand:
    """Test suite for update_password command."""

    def test_update_password_requires_auth(self, test_db, session_manager):
        """Test that update_password requires authentication."""
        result = update_password(
            "github", "newpassword", session_manager=session_manager
        )

        assert result is None

    def test_update_password_success(self, test_db, authenticated_user):
        """Test successful password update."""
        # Save initial password
        save_password("github", "oldpassword", session_manager=authenticated_user)

        # Update password
        update_password("github", "newpassword", session_manager=authenticated_user)

        # Verify update
        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        password_data = repo.get_password_by_resource_name(
            authenticated_user.get_user_id(),
            authenticated_user.get_encryption_key(),
            "github",
        )

        assert password_data["password"] == "newpassword"

    def test_update_password_with_metadata(self, test_db, authenticated_user):
        """Test updating password with metadata."""
        # Save initial password
        save_password("github", "oldpassword", session_manager=authenticated_user)

        # Update with metadata
        update_password(
            "github",
            "newpassword",
            username="newuser",
            website="https://github.com/new",
            session_manager=authenticated_user,
        )

        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        password_data = repo.get_password_by_resource_name(
            authenticated_user.get_user_id(),
            authenticated_user.get_encryption_key(),
            "github",
        )

        assert password_data["password"] == "newpassword"
        assert password_data["username"] == "newuser"

    def test_update_nonexistent_password(self, test_db, authenticated_user):
        """Test updating non-existent password."""
        update_password(
            "nonexistent", "newpassword", session_manager=authenticated_user
        )


class TestDeletePasswordCommand:
    """Test suite for delete_password command."""

    def test_delete_password_requires_auth(self, test_db, session_manager):
        """Test that delete_password requires authentication."""
        result = delete_password("github", session_manager=session_manager)

        assert result is None

    def test_delete_password_success(self, test_db, authenticated_user):
        """Test successful password deletion."""
        # Save password
        save_password("github", "password123", session_manager=authenticated_user)

        # Delete password
        delete_password("github", session_manager=authenticated_user)

        # Verify deletion - should raise ResourceNotFoundError
        from passwault.core.database.password_manager import PasswordRepository
        from passwault.core.utils.local_types import ResourceNotFoundError

        repo = PasswordRepository()
        with pytest.raises(ResourceNotFoundError):
            repo.get_password_by_resource_name(
                authenticated_user.get_user_id(),
                authenticated_user.get_encryption_key(),
                "github",
            )

    def test_delete_nonexistent_password(self, test_db, authenticated_user):
        """Test deleting non-existent password."""
        delete_password("nonexistent", session_manager=authenticated_user)


class TestGeneratePasswordCommand:
    """Test suite for generate_password command."""

    def test_generate_password_default(self):
        """Test password generation with default settings."""
        generate_password()

    def test_generate_password_custom_length(self):
        """Test password generation with custom length."""
        generate_password(password_length=20)

    def test_generate_password_no_symbols(self):
        """Test password generation without symbols."""
        generate_password(has_symbols=False)

    def test_generate_password_no_digits(self):
        """Test password generation without digits."""
        generate_password(has_digits=False)

    def test_generate_password_no_uppercase(self):
        """Test password generation without uppercase."""
        generate_password(has_uppercase=False)

    def test_generate_password_all_options_disabled(self):
        """Test password generation with all options disabled (only lowercase)."""
        generate_password(
            password_length=12, has_symbols=False, has_digits=False, has_uppercase=False
        )


class TestPasswordCommandsIntegration:
    """Integration tests for password commands."""

    def test_full_password_lifecycle(self, test_db, authenticated_user):
        """Test complete password lifecycle: save -> load -> update -> delete."""
        # Save
        save_password("github", "password123", session_manager=authenticated_user)

        # Load
        load_password(resource_name="github", session_manager=authenticated_user)

        # Update
        update_password("github", "newpassword", session_manager=authenticated_user)

        # Load again to verify update
        load_password(resource_name="github", session_manager=authenticated_user)

        # Delete
        delete_password("github", session_manager=authenticated_user)

        # Verify deletion - should raise ResourceNotFoundError
        from passwault.core.database.password_manager import PasswordRepository
        from passwault.core.utils.local_types import ResourceNotFoundError

        repo = PasswordRepository()
        with pytest.raises(ResourceNotFoundError):
            repo.get_password_by_resource_name(
                authenticated_user.get_user_id(),
                authenticated_user.get_encryption_key(),
                "github",
            )

    def test_multiple_passwords_for_user(self, test_db, authenticated_user):
        """Test managing multiple passwords for a user."""
        # Save multiple passwords
        save_password("github", "pass1", session_manager=authenticated_user)
        save_password("gitlab", "pass2", session_manager=authenticated_user)
        save_password("bitbucket", "pass3", session_manager=authenticated_user)

        # Load all
        load_password(all_passwords=True, session_manager=authenticated_user)

        # Delete one
        delete_password("gitlab", session_manager=authenticated_user)

        # Verify only 2 remain
        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        passwords = repo.get_all_passwords(
            authenticated_user.get_user_id(),
            authenticated_user.get_encryption_key(),
        )
        assert len(passwords) == 2

    def test_commands_block_after_logout(self, test_db, authenticated_user):
        """Test that commands are blocked after logout."""
        # Save password while logged in
        save_password("github", "password123", session_manager=authenticated_user)

        # Logout
        authenticated_user.logout()

        # Try to save another password (should be blocked)
        result = save_password(
            "gitlab", "password456", session_manager=authenticated_user
        )
        assert result is None

        # Try to load password (should be blocked)
        result = load_password(
            resource_name="github", session_manager=authenticated_user
        )
        assert result is None
