"""Session management for user authentication and encryption key caching.

This module handles user sessions, including:
- Session persistence (encrypted on disk)
- Encryption key caching (in-memory only)
- Session timeout and expiration
- Secure cleanup on logout
"""

import json
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from functools import wraps
from os import path, remove
from pathlib import Path
from typing import Optional, Dict, Any
from passwault.core.utils.logger import Logger


def check_session(func):
    """Decorator to check if user is logged in before executing function.

    DEPRECATED: Use @require_auth decorator from decorators.py instead.
    This decorator is kept for backward compatibility with existing code.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not args:
            raise ValueError("No position arguments provided, session is missing")

        session = args[-1].session_manager

        if not isinstance(session, SessionManager):
            raise TypeError("Last object is not a session object")

        if not session.is_logged_in():
            Logger.info("User is not logged in")
            return

        func(*args, **kwargs)

    return wrapper


class SessionManager:
    """Manages user sessions and encryption key caching.

    Security features:
    - Session data encrypted on disk with Fernet (symmetric encryption)
    - Encryption keys stored in memory only (never persisted to disk)
    - Automatic session expiration after 10 minutes of inactivity
    - Secure cleanup on logout (clears both session and encryption key)

    Session file contains only non-sensitive data:
    - user_id: User's database ID
    - username: Username
    - timestamp: Session creation/update time

    Encryption key is cached in _encryption_key_cache (in-memory only).
    """

    # Session timeout in minutes
    SESSION_TIMEOUT_MINUTES = 10

    def __init__(self, session_file: str = ".session"):
        """Initialize session manager.

        Args:
            session_file: Name of session file (default: .session)
        """
        self.root_path = Path(__file__).resolve().parents[4]
        self.session_file_path = self.root_path / session_file
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()

        # In-memory encryption key cache (NEVER persisted to disk)
        self._encryption_key_cache: Optional[bytes] = None

    def _create_secret_key(self):
        """Create Fernet encryption key for session file encryption."""
        if not path.isfile(self.key_file_path):
            key = Fernet.generate_key()
            with open(self.key_file_path, "wb") as f:
                f.write(key)

    def _get_secret_key(self) -> bytes:
        """Retrieve Fernet encryption key for session file encryption."""
        with open(self.key_file_path, "rb") as f:
            return f.read()

    def _load_session(self) -> Optional[Dict[str, Any]]:
        """Load and decrypt session from disk.

        Returns:
            Session data dict if exists, None otherwise
        """
        if path.exists(self.session_file_path):
            if not path.isfile(self.key_file_path):
                raise Exception("Error loading session. There is no secret key")

            # Retrieve encryption key
            secret_key = self._get_secret_key()
            fernet = Fernet(secret_key)

            with open(self.session_file_path, "rb") as sf:
                encrypted_session = sf.read()

            decrypted_data = fernet.decrypt(encrypted_session)

            return json.loads(decrypted_data.decode())

        return None

    def _save_session(self):
        """Encrypt and save session to disk.

        Only saves non-sensitive session data (user_id, username, timestamp).
        Encryption key is NEVER saved to disk.
        """
        if self.session is None:
            return

        # Creates an encryption key if not exists then retrieve it
        self._create_secret_key()
        secret_key = self._get_secret_key()
        fernet = Fernet(secret_key)

        # Update timestamp
        self.session["timestamp"] = datetime.now().isoformat()

        # Encrypt session (only non-sensitive data)
        encrypted_session = fernet.encrypt(json.dumps(self.session).encode())

        with open(self.session_file_path, "wb") as sf:
            sf.write(encrypted_session)

    def is_logged_in(self) -> bool:
        """Check if user has an active session.

        Returns:
            True if session exists and not expired, False otherwise
        """
        if self.session is None:
            return False

        # Check if session has expired
        self.expire_session()

        return self.session is not None

    def create_session(self, user_data: Dict[str, Any]) -> None:
        """Create a new user session with encryption key caching.

        Extracts and caches the encryption key from user_data, then saves
        only non-sensitive session data to disk.

        Args:
            user_data: Dictionary containing:
                - user_id: User's database ID
                - username: Username
                - encryption_key: Derived encryption key (cached in memory)
                - Other optional fields (not persisted)

        Security:
            - encryption_key is cached in memory only
            - Session file contains only user_id, username, timestamp
        """
        # Extract and cache encryption key (NEVER persisted)
        if "encryption_key" in user_data:
            self._encryption_key_cache = user_data["encryption_key"]

        # Create session with only non-sensitive data
        self.session = {
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "timestamp": datetime.now().isoformat(),
        }

        self._save_session()

    def get_encryption_key(self) -> Optional[bytes]:
        """Retrieve cached encryption key from memory.

        Returns:
            Cached encryption key (32 bytes) if session is active, None otherwise

        Security:
            - Key is only available during active session
            - Key is cleared on logout or expiration
            - Key is NEVER persisted to disk
        """
        if not self.is_logged_in():
            return None

        return self._encryption_key_cache

    def get_user_id(self) -> Optional[int]:
        """Get current user's ID from session.

        Returns:
            User ID if logged in, None otherwise
        """
        if self.session is None:
            return None
        return self.session.get("user_id")

    def get_username(self) -> Optional[str]:
        """Get current user's username from session.

        Returns:
            Username if logged in, None otherwise
        """
        if self.session is None:
            return None
        return self.session.get("username")

    def logout(self) -> None:
        """Log out user and clear all session data.

        Security:
            - Clears encryption key from memory
            - Removes session file from disk
            - Nullifies session object
        """
        # Clear encryption key from memory
        self._encryption_key_cache = None

        # Clear session
        self.session = None

        # Remove session file
        if path.exists(self.session_file_path):
            remove(self.session_file_path)

    def get_session(self) -> Optional[Dict[str, Any]]:
        """Get current session data.

        Returns:
            Session data dict (without encryption key) if logged in, None otherwise
        """
        return self.session

    def expire_session(self) -> None:
        """Check and expire session if timeout exceeded.

        Sessions expire after SESSION_TIMEOUT_MINUTES of inactivity.
        Expired sessions are automatically logged out.
        """
        if self.session is None:
            return

        if "timestamp" in self.session:
            time_difference = datetime.now() - datetime.fromisoformat(
                self.session["timestamp"]
            )
            if time_difference >= timedelta(minutes=self.SESSION_TIMEOUT_MINUTES):
                Logger.info("Session expired due to inactivity")
                self.logout()
