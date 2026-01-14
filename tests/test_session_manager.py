"""Unit tests for SessionManager.

Tests session management including:
- Session creation and persistence
- Encryption key caching (in-memory only)
- Session expiration and timeout
- Logout and cleanup
- Security measures
"""

import os
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from cryptography.fernet import Fernet

from passwault.core.utils.session_manager import SessionManager


@pytest.fixture
def temp_session_dir():
    """Create a temporary directory for session files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def session_manager(temp_session_dir):
    """Create SessionManager instance with temporary session file."""
    session_file = temp_session_dir / ".session"
    key_file = temp_session_dir / ".enckey"

    # Patch the root_path to use temp directory
    with patch.object(
        SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
    ):
        manager = SessionManager()
        yield manager

        # Cleanup
        if session_file.exists():
            session_file.unlink()
        if key_file.exists():
            key_file.unlink()


def _init_with_temp(self, temp_dir, session_file):
    """Helper to initialize SessionManager with temp directory."""
    self.root_path = temp_dir
    self.session_file_path = self.root_path / session_file
    self.key_file_path = self.root_path / ".enckey"
    self.session = self._load_session()
    self._encryption_key_cache = None


class TestSessionManagerInitialization:
    """Test suite for SessionManager initialization."""

    def test_init_no_existing_session(self, temp_session_dir):
        """Test initialization with no existing session."""
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            manager = SessionManager()

            assert manager.session is None
            assert manager._encryption_key_cache is None
            assert not manager.is_logged_in()

    def test_init_creates_paths(self, temp_session_dir):
        """Test that initialization sets correct file paths."""
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            manager = SessionManager()

            assert manager.root_path == temp_session_dir
            assert manager.session_file_path == temp_session_dir / ".session"
            assert manager.key_file_path == temp_session_dir / ".enckey"


class TestSessionCreation:
    """Test suite for session creation."""

    def test_create_session_basic(self, session_manager):
        """Test creating a basic session."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert session_manager.is_logged_in()
        assert session_manager.get_user_id() == 1
        assert session_manager.get_username() == "testuser"

    def test_create_session_caches_encryption_key(self, session_manager):
        """Test that encryption key is cached in memory."""
        encryption_key = b"test_encryption_key_32_bytes!!"
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": encryption_key,
        }

        session_manager.create_session(user_data)

        cached_key = session_manager.get_encryption_key()
        assert cached_key == encryption_key
        assert session_manager._encryption_key_cache == encryption_key

    def test_create_session_saves_to_disk(self, session_manager):
        """Test that session is saved to disk."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert session_manager.session_file_path.exists()

    def test_create_session_encrypts_file(self, session_manager):
        """Test that session file is encrypted."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        # Read raw session file
        with open(session_manager.session_file_path, "rb") as f:
            raw_data = f.read()

        # Should be encrypted (not plain JSON)
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw_data)

    def test_create_session_persists_encrypted_key(self, session_manager):
        """Test that encryption key IS saved to disk (encrypted).

        The encryption key is now persisted in the encrypted session file
        to support multi-invocation CLI usage while maintaining security.
        """
        encryption_key = b"secret_key_should_be_encrypted!"
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": encryption_key,
        }

        session_manager.create_session(user_data)

        # Load session file and verify encryption key IS there (encrypted)
        secret_key = session_manager._get_secret_key()
        fernet = Fernet(secret_key)

        with open(session_manager.session_file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        session_data = json.loads(decrypted_data.decode())

        # Encryption key SHOULD be in encrypted session file
        assert "encryption_key" in session_data
        assert "user_id" in session_data
        assert "username" in session_data

        # Verify encryption key is stored as base64 and can be decoded
        import base64
        decoded_key = base64.b64decode(session_data["encryption_key"])
        assert decoded_key == encryption_key

    def test_create_session_adds_timestamp(self, session_manager):
        """Test that session includes timestamp."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert "timestamp" in session_manager.session
        timestamp = datetime.fromisoformat(session_manager.session["timestamp"])
        assert isinstance(timestamp, datetime)


class TestSessionPersistence:
    """Test suite for session persistence and loading."""

    def test_load_existing_session(self, temp_session_dir):
        """Test loading an existing session from disk."""
        # Create first manager and session
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            manager1 = SessionManager()
            user_data = {
                "user_id": 1,
                "username": "testuser",
                "encryption_key": b"0" * 32,
            }
            manager1.create_session(user_data)

            # Create second manager (simulates app restart)
            manager2 = SessionManager()

            # Session should be loaded
            assert manager2.is_logged_in()
            assert manager2.get_user_id() == 1
            assert manager2.get_username() == "testuser"

    def test_encryption_key_not_loaded_from_disk(self, temp_session_dir):
        """Test that encryption key is NOT restored from disk."""
        # Create first manager and session
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            manager1 = SessionManager()
            encryption_key = b"secret_key_32_bytes_for_test"
            user_data = {
                "user_id": 1,
                "username": "testuser",
                "encryption_key": encryption_key,
            }
            manager1.create_session(user_data)

            # Verify key is cached
            assert manager1.get_encryption_key() == encryption_key

            # Create second manager (simulates app restart)
            manager2 = SessionManager()

            # Session exists but encryption key is NOT cached
            assert manager2.is_logged_in()
            assert manager2.get_encryption_key() is None


class TestEncryptionKeyCaching:
    """Test suite for encryption key caching."""

    def test_get_encryption_key_when_logged_in(self, session_manager):
        """Test retrieving encryption key when logged in."""
        encryption_key = b"0" * 32
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": encryption_key,
        }

        session_manager.create_session(user_data)

        assert session_manager.get_encryption_key() == encryption_key

    def test_get_encryption_key_when_not_logged_in(self, session_manager):
        """Test that encryption key is None when not logged in."""
        assert session_manager.get_encryption_key() is None

    def test_encryption_key_cleared_on_logout(self, session_manager):
        """Test that encryption key is cleared from memory on logout."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        assert session_manager.get_encryption_key() is not None

        session_manager.logout()

        assert session_manager.get_encryption_key() is None
        assert session_manager._encryption_key_cache is None


class TestSessionRetrieval:
    """Test suite for session data retrieval."""

    def test_get_user_id(self, session_manager):
        """Test getting user ID from session."""
        user_data = {
            "user_id": 42,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert session_manager.get_user_id() == 42

    def test_get_user_id_when_not_logged_in(self, session_manager):
        """Test that user ID is None when not logged in."""
        assert session_manager.get_user_id() is None

    def test_get_username(self, session_manager):
        """Test getting username from session."""
        user_data = {
            "user_id": 1,
            "username": "myusername",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert session_manager.get_username() == "myusername"

    def test_get_username_when_not_logged_in(self, session_manager):
        """Test that username is None when not logged in."""
        assert session_manager.get_username() is None

    def test_get_session(self, session_manager):
        """Test getting full session data."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        session_data = session_manager.get_session()

        assert session_data is not None
        assert session_data["user_id"] == 1
        assert session_data["username"] == "testuser"
        assert "timestamp" in session_data
        assert "encryption_key" not in session_data  # Should not be in session


class TestIsLoggedIn:
    """Test suite for is_logged_in check."""

    def test_is_logged_in_with_active_session(self, session_manager):
        """Test is_logged_in returns True with active session."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        assert session_manager.is_logged_in() is True

    def test_is_logged_in_without_session(self, session_manager):
        """Test is_logged_in returns False without session."""
        assert session_manager.is_logged_in() is False

    def test_is_logged_in_after_logout(self, session_manager):
        """Test is_logged_in returns False after logout."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        assert session_manager.is_logged_in() is True

        session_manager.logout()
        assert session_manager.is_logged_in() is False


class TestLogout:
    """Test suite for logout functionality."""

    def test_logout_clears_session(self, session_manager):
        """Test that logout clears session object."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        session_manager.logout()

        assert session_manager.session is None

    def test_logout_clears_encryption_key(self, session_manager):
        """Test that logout clears encryption key from memory."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"secret_key" * 4,
        }

        session_manager.create_session(user_data)
        session_manager.logout()

        assert session_manager._encryption_key_cache is None
        assert session_manager.get_encryption_key() is None

    def test_logout_removes_session_file(self, session_manager):
        """Test that logout removes session file from disk."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        assert session_manager.session_file_path.exists()

        session_manager.logout()

        assert not session_manager.session_file_path.exists()

    def test_logout_when_not_logged_in(self, session_manager):
        """Test that logout is safe when not logged in."""
        # Should not raise exception
        session_manager.logout()

        assert session_manager.session is None
        assert session_manager._encryption_key_cache is None


class TestSessionExpiration:
    """Test suite for session expiration and timeout."""

    def test_session_expires_after_timeout(self, session_manager):
        """Test that session expires after timeout period."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        # Manually set timestamp to past (more than 10 minutes ago)
        past_time = datetime.now() - timedelta(minutes=11)
        session_manager.session["timestamp"] = past_time.isoformat()

        # Check if logged in (should trigger expiration)
        assert session_manager.is_logged_in() is False

    def test_session_does_not_expire_before_timeout(self, session_manager):
        """Test that session does not expire before timeout."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        # Set timestamp to recent (less than 10 minutes ago)
        recent_time = datetime.now() - timedelta(minutes=5)
        session_manager.session["timestamp"] = recent_time.isoformat()

        # Should still be logged in
        assert session_manager.is_logged_in() is True

    def test_expire_session_clears_encryption_key(self, session_manager):
        """Test that session expiration clears encryption key."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"secret_key" * 4,
        }

        session_manager.create_session(user_data)

        # Force expiration
        past_time = datetime.now() - timedelta(minutes=11)
        session_manager.session["timestamp"] = past_time.isoformat()

        # Trigger expiration
        session_manager.is_logged_in()

        # Encryption key should be cleared
        assert session_manager.get_encryption_key() is None

    def test_expire_session_removes_session_file(self, session_manager):
        """Test that session expiration removes session file."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)
        assert session_manager.session_file_path.exists()

        # Force expiration
        past_time = datetime.now() - timedelta(minutes=11)
        session_manager.session["timestamp"] = past_time.isoformat()

        # Trigger expiration
        session_manager.is_logged_in()

        # Session file should be removed
        assert not session_manager.session_file_path.exists()


class TestSessionSecurity:
    """Test suite for session security measures."""

    def test_session_file_is_encrypted(self, session_manager):
        """Test that session file content is encrypted."""
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"0" * 32,
        }

        session_manager.create_session(user_data)

        # Read raw file
        with open(session_manager.session_file_path, "rb") as f:
            raw_content = f.read()

        # Should not contain plain text username
        assert b"testuser" not in raw_content

    def test_session_file_contains_encrypted_key(self, session_manager):
        """Test that session file contains encryption key (encrypted).

        The encryption key is now persisted in the encrypted session file
        to support multi-invocation CLI usage.
        """
        encryption_key = b"very_secret_encryption_key_32b"
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": encryption_key,
        }

        session_manager.create_session(user_data)

        # Read and decrypt session file
        secret_key = session_manager._get_secret_key()
        fernet = Fernet(secret_key)

        with open(session_manager.session_file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        session_content = decrypted_data.decode()

        # Encryption key SHOULD be in file (as base64)
        assert "encryption_key" in session_content

        # Verify it can be restored correctly
        import json
        import base64
        session_data = json.loads(session_content)
        restored_key = base64.b64decode(session_data["encryption_key"])
        assert restored_key == encryption_key

    def test_different_users_have_different_sessions(self, temp_session_dir):
        """Test that different users have isolated sessions."""
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            manager = SessionManager()

            # User 1
            user1_data = {
                "user_id": 1,
                "username": "user1",
                "encryption_key": b"key1" * 8,
            }
            manager.create_session(user1_data)

            assert manager.get_user_id() == 1
            assert manager.get_encryption_key() == b"key1" * 8

            # Logout and login as User 2
            manager.logout()

            user2_data = {
                "user_id": 2,
                "username": "user2",
                "encryption_key": b"key2" * 8,
            }
            manager.create_session(user2_data)

            # Should be user 2's data now
            assert manager.get_user_id() == 2
            assert manager.get_encryption_key() == b"key2" * 8


class TestSessionManagerIntegration:
    """Integration tests for SessionManager."""

    def test_full_session_lifecycle(self, session_manager):
        """Test complete session lifecycle: create -> use -> logout."""
        # Create session
        encryption_key = b"test_encryption_key_32_bytes!!"
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": encryption_key,
        }

        session_manager.create_session(user_data)

        # Verify session is active
        assert session_manager.is_logged_in()
        assert session_manager.get_user_id() == 1
        assert session_manager.get_username() == "testuser"
        assert session_manager.get_encryption_key() == encryption_key

        # Logout
        session_manager.logout()

        # Verify everything is cleared
        assert not session_manager.is_logged_in()
        assert session_manager.get_user_id() is None
        assert session_manager.get_username() is None
        assert session_manager.get_encryption_key() is None
        assert not session_manager.session_file_path.exists()

    def test_session_persistence_across_instances(self, temp_session_dir):
        """Test that session persists across SessionManager instances."""
        with patch.object(
            SessionManager, "__init__", lambda self, sf=".session": _init_with_temp(self, temp_session_dir, sf)
        ):
            # Create session with first instance
            manager1 = SessionManager()
            user_data = {
                "user_id": 1,
                "username": "testuser",
                "encryption_key": b"0" * 32,
            }
            manager1.create_session(user_data)

            # Create second instance (simulates app restart)
            manager2 = SessionManager()

            # Session should be loaded
            assert manager2.is_logged_in()
            assert manager2.get_user_id() == 1
            assert manager2.get_username() == "testuser"

            # But encryption key should NOT be loaded
            assert manager2.get_encryption_key() is None

    def test_multiple_login_logout_cycles(self, session_manager):
        """Test multiple login/logout cycles."""
        for i in range(3):
            user_data = {
                "user_id": i + 1,
                "username": f"user{i + 1}",
                "encryption_key": bytes([i] * 32),
            }

            session_manager.create_session(user_data)
            assert session_manager.is_logged_in()
            assert session_manager.get_user_id() == i + 1

            session_manager.logout()
            assert not session_manager.is_logged_in()
