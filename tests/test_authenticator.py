"""Unit tests for authentication commands.

Tests user registration, login, and logout functionality including
password prompting, validation, and session management.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from passwault.core.commands.authenticator import (
    change_master_password,
    login,
    logout,
    register,
)
from passwault.core.database.models import Base, User
from passwault.core.utils.session_manager import SessionManager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


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
    session_file = temp_session_dir / ".session"
    key_file = temp_session_dir / ".enckey"

    def _init_with_temp(self, sf=".session"):
        self.root_path = temp_session_dir
        self.session_file_path = self.root_path / sf
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()
        self._encryption_key_cache = None

    with patch.object(SessionManager, "__init__", _init_with_temp):
        manager = SessionManager()
        yield manager

        if session_file.exists():
            session_file.unlink()
        if key_file.exists():
            key_file.unlink()


class TestRegisterCommand:
    """Test suite for register command."""

    def test_register_with_password_provided(self, test_db, session_manager):
        """Test registration with password provided as argument."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        # Verify user was created
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is not None
            assert user.username == "testuser"
            assert user.email == "test@example.com"
        finally:
            session.close()

    def test_register_without_email(self, test_db, session_manager):
        """Test registration without email (optional field)."""
        register("testuser", "SecurePass123!", None, session_manager)

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is not None
            assert user.email is None
        finally:
            session.close()

    def test_register_with_password_prompt(self, test_db, session_manager):
        """Test registration with password prompt."""
        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            # First call for password, second for confirmation
            mock_get_pass.side_effect = ["SecurePass123!", "SecurePass123!"]

            register("testuser", None, "test@example.com", session_manager)

            assert mock_get_pass.call_count == 2

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is not None
        finally:
            session.close()

    def test_register_password_mismatch(self, test_db, session_manager):
        """Test registration fails when password confirmation doesn't match."""
        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            # Password and confirmation don't match
            mock_get_pass.side_effect = ["SecurePass123!", "DifferentPass456!"]

            register("testuser", None, "test@example.com", session_manager)

        # Verify user was NOT created
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is None
        finally:
            session.close()

    def test_register_empty_password(self, test_db, session_manager):
        """Test registration fails with empty password."""
        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            mock_get_pass.return_value = ""

            register("testuser", None, "test@example.com", session_manager)

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user is None
        finally:
            session.close()

    def test_register_duplicate_username(self, test_db, session_manager):
        """Test registration fails with duplicate username."""
        # Register first user
        register("testuser", "SecurePass123!", "test1@example.com", session_manager)

        # Try to register with same username
        register("testuser", "AnotherPass456!", "test2@example.com", session_manager)

        # Verify only one user exists
        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            users = session.query(User).filter_by(username="testuser").all()
            assert len(users) == 1
            assert users[0].email == "test1@example.com"
        finally:
            session.close()


class TestLoginCommand:
    """Test suite for login command."""

    def test_login_success(self, test_db, session_manager):
        """Test successful login."""
        # Register user first
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        # Login
        login("testuser", "SecurePass123!", session_manager)

        # Verify session was created
        assert session_manager.is_logged_in()
        assert session_manager.get_username() == "testuser"
        assert session_manager.get_encryption_key() is not None

    def test_login_wrong_password(self, test_db, session_manager):
        """Test login fails with wrong password."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        # Try to login with wrong password
        login("testuser", "WrongPassword!", session_manager)

        # Verify session was NOT created
        assert not session_manager.is_logged_in()

    def test_login_nonexistent_user(self, test_db, session_manager):
        """Test login fails with non-existent user."""
        login("nonexistent", "Password123!", session_manager)

        assert not session_manager.is_logged_in()

    def test_login_with_password_prompt(self, test_db, session_manager):
        """Test login with password prompt."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            mock_get_pass.return_value = "SecurePass123!"

            login("testuser", None, session_manager)

            mock_get_pass.assert_called_once()

        assert session_manager.is_logged_in()

    def test_login_empty_password(self, test_db, session_manager):
        """Test login fails with empty password."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            mock_get_pass.return_value = ""

            login("testuser", None, session_manager)

        assert not session_manager.is_logged_in()

    def test_login_creates_encryption_key(self, test_db, session_manager):
        """Test login creates and caches encryption key."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        login("testuser", "SecurePass123!", session_manager)

        encryption_key = session_manager.get_encryption_key()
        assert encryption_key is not None
        assert isinstance(encryption_key, bytes)
        assert len(encryption_key) == 32  # 256 bits

    def test_login_updates_last_login(self, test_db, session_manager):
        """Test login updates last_login timestamp."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        login("testuser", "SecurePass123!", session_manager)

        from passwault.core.database.models import SessionLocal

        session = SessionLocal()
        try:
            user = session.query(User).filter_by(username="testuser").first()
            assert user.last_login is not None
        finally:
            session.close()


class TestLogoutCommand:
    """Test suite for logout command."""

    def test_logout_success(self, test_db, session_manager):
        """Test successful logout."""
        # Register and login
        register("testuser", "SecurePass123!", "test@example.com", session_manager)
        login("testuser", "SecurePass123!", session_manager)

        assert session_manager.is_logged_in()

        # Logout
        logout(session_manager)

        # Verify session was cleared
        assert not session_manager.is_logged_in()
        assert session_manager.get_encryption_key() is None

    def test_logout_without_session(self, test_db, session_manager):
        """Test logout when not logged in."""
        # Should not raise error
        logout(session_manager)

        assert not session_manager.is_logged_in()

    def test_logout_clears_encryption_key(self, test_db, session_manager):
        """Test logout clears encryption key from memory."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)
        login("testuser", "SecurePass123!", session_manager)

        # Verify key exists
        assert session_manager.get_encryption_key() is not None

        # Logout
        logout(session_manager)

        # Verify key is cleared
        assert session_manager.get_encryption_key() is None

    def test_logout_removes_session_file(self, test_db, session_manager):
        """Test logout removes session file from disk."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)
        login("testuser", "SecurePass123!", session_manager)

        # Verify session file exists
        assert session_manager.session_file_path.exists()

        # Logout
        logout(session_manager)

        # Verify session file was removed
        assert not session_manager.session_file_path.exists()


class TestAuthenticationFlow:
    """Integration tests for authentication flow."""

    def test_full_authentication_flow(self, test_db, session_manager):
        """Test complete flow: register -> login -> logout."""
        # Register
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        # Login
        login("testuser", "SecurePass123!", session_manager)
        assert session_manager.is_logged_in()
        assert session_manager.get_username() == "testuser"

        # Logout
        logout(session_manager)
        assert not session_manager.is_logged_in()

    def test_multiple_login_logout_cycles(self, test_db, session_manager):
        """Test multiple login/logout cycles."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)

        # First cycle
        login("testuser", "SecurePass123!", session_manager)
        assert session_manager.is_logged_in()
        logout(session_manager)
        assert not session_manager.is_logged_in()

        # Second cycle
        login("testuser", "SecurePass123!", session_manager)
        assert session_manager.is_logged_in()
        logout(session_manager)
        assert not session_manager.is_logged_in()

    def test_login_after_registration(self, test_db, session_manager):
        """Test login immediately after registration."""
        register("testuser", "SecurePass123!", "test@example.com", session_manager)
        login("testuser", "SecurePass123!", session_manager)

        assert session_manager.is_logged_in()
        assert session_manager.get_encryption_key() is not None

    def test_multiple_users(self, test_db, temp_session_dir):
        """Test multiple users with separate sessions."""

        # Create two session managers for two users
        def create_session_manager():
            def _init_with_temp(self, sf=".session"):
                self.root_path = temp_session_dir
                self.session_file_path = self.root_path / sf
                self.key_file_path = self.root_path / ".enckey"
                self.session = self._load_session()
                self._encryption_key_cache = None

            with patch.object(SessionManager, "__init__", _init_with_temp):
                return SessionManager()

        sm1 = create_session_manager()
        sm2 = create_session_manager()

        # Register two users
        register("user1", "Pass1!", "user1@example.com", sm1)
        register("user2", "Pass2!", "user2@example.com", sm2)

        # Login as user1
        login("user1", "Pass1!", sm1)
        assert sm1.get_username() == "user1"

        # Login as user2 (this will replace user1's session in the file)
        login("user2", "Pass2!", sm2)
        assert sm2.get_username() == "user2"

        # Both have different encryption keys (even though they share session file)
        key1 = sm1.get_encryption_key()
        key2 = sm2.get_encryption_key()
        assert key1 != key2


class TestChangeMasterPassword:
    """Test suite for change_master_password command."""

    def test_change_password_success(self, test_db, session_manager):
        """Test successfully changing master password."""
        # Register and login
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        # Save a password to verify re-encryption works
        from passwault.core.commands.password import save_password

        save_password(
            resource_name="github",
            password="mypassword",
            session_manager=session_manager,
        )

        # Change master password
        change_master_password("OldPass123!", "NewPass456!", session_manager)

        # Verify we can logout and login with new password
        logout(session_manager)
        login("testuser", "NewPass456!", session_manager)

        assert session_manager.is_logged_in()

        # Verify password was re-encrypted and can be decrypted with new key
        from passwault.core.commands.password import load_password
        from io import StringIO
        import sys

        # Capture output
        captured_output = StringIO()
        sys.stdout = captured_output
        load_password(resource_name="github", session_manager=session_manager)
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        assert "github" in output
        assert "mypassword" in output

    def test_change_password_wrong_old_password(self, test_db, session_manager):
        """Test change password fails with wrong old password."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        # Try to change with wrong old password
        change_master_password("WrongOldPass!", "NewPass456!", session_manager)

        # Verify password was NOT changed (can still login with old password)
        logout(session_manager)
        login("testuser", "OldPass123!", session_manager)

        assert session_manager.is_logged_in()

        # Verify new password doesn't work
        logout(session_manager)
        login("testuser", "NewPass456!", session_manager)

        assert not session_manager.is_logged_in()

    def test_change_password_same_as_old(self, test_db, session_manager):
        """Test change password fails when new password equals old password."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        # Try to change to same password
        change_master_password("OldPass123!", "OldPass123!", session_manager)

        # Should still be logged in (operation should fail gracefully)
        assert session_manager.is_logged_in()

    def test_change_password_with_prompts(self, test_db, session_manager):
        """Test change password with password prompts."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            # First call for old password, second for new, third for confirmation
            mock_get_pass.side_effect = ["OldPass123!", "NewPass456!", "NewPass456!"]

            change_master_password(None, None, session_manager)

            assert mock_get_pass.call_count == 3

        # Verify password was changed
        logout(session_manager)
        login("testuser", "NewPass456!", session_manager)

        assert session_manager.is_logged_in()

    def test_change_password_prompt_mismatch(self, test_db, session_manager):
        """Test change password fails when new password confirmation doesn't match."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            # Old password correct, but new password and confirmation don't match
            mock_get_pass.side_effect = [
                "OldPass123!",
                "NewPass456!",
                "DifferentPass789!",
            ]

            change_master_password(None, None, session_manager)

        # Verify password was NOT changed
        logout(session_manager)
        login("testuser", "OldPass123!", session_manager)

        assert session_manager.is_logged_in()

    def test_change_password_reencrypts_multiple_passwords(
        self, test_db, session_manager
    ):
        """Test change password re-encrypts multiple passwords correctly."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        # Save multiple passwords
        from passwault.core.commands.password import save_password

        save_password("github", "github_pass", session_manager=session_manager)
        save_password("gitlab", "gitlab_pass", session_manager=session_manager)
        save_password("bitbucket", "bitbucket_pass", session_manager=session_manager)

        # Change master password
        change_master_password("OldPass123!", "NewPass456!", session_manager)

        # Verify all passwords can still be decrypted
        from passwault.core.database.password_manager import PasswordRepository

        repo = PasswordRepository()
        user_id = session_manager.get_user_id()
        encryption_key = session_manager.get_encryption_key()

        passwords = repo.get_all_passwords(user_id, encryption_key)
        assert len(passwords) == 3

        # Verify specific passwords
        github = repo.get_password_by_resource_name(user_id, encryption_key, "github")
        assert github["password"] == "github_pass"

        gitlab = repo.get_password_by_resource_name(user_id, encryption_key, "gitlab")
        assert gitlab["password"] == "gitlab_pass"

        bitbucket = repo.get_password_by_resource_name(
            user_id, encryption_key, "bitbucket"
        )
        assert bitbucket["password"] == "bitbucket_pass"

    def test_change_password_updates_session(self, test_db, session_manager):
        """Test change password updates session with new encryption key."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        old_encryption_key = session_manager.get_encryption_key()

        # Change master password
        change_master_password("OldPass123!", "NewPass456!", session_manager)

        new_encryption_key = session_manager.get_encryption_key()

        # Verify encryption key changed
        assert old_encryption_key != new_encryption_key
        # Verify still logged in
        assert session_manager.is_logged_in()

    def test_change_password_empty_new_password(self, test_db, session_manager):
        """Test change password fails with empty new password."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        with patch(
            "passwault.core.commands.authenticator.get_password_with_mask"
        ) as mock_get_pass:
            # Old password correct, but new password is empty
            mock_get_pass.side_effect = ["OldPass123!", ""]

            change_master_password(None, None, session_manager)

        # Verify password was NOT changed
        logout(session_manager)
        login("testuser", "OldPass123!", session_manager)

        assert session_manager.is_logged_in()

    def test_change_password_requires_auth(self, test_db, session_manager):
        """Test change password requires authentication."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        # Don't login

        # Try to change password without being logged in
        result = change_master_password("OldPass123!", "NewPass456!", session_manager)

        # Should return None (blocked by @require_auth decorator)
        assert result is None

    def test_change_password_no_existing_passwords(self, test_db, session_manager):
        """Test change password works even with no existing passwords."""
        register("testuser", "OldPass123!", "test@example.com", session_manager)
        login("testuser", "OldPass123!", session_manager)

        # Change password without saving any passwords
        change_master_password("OldPass123!", "NewPass456!", session_manager)

        # Verify password was changed
        logout(session_manager)
        login("testuser", "NewPass456!", session_manager)

        assert session_manager.is_logged_in()
