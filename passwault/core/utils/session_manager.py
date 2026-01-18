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
from typing import Optional, Dict, Any
from passwault.core.utils.data_dir import get_data_dir
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
    - Encryption key encrypted within session file for multi-invocation support
    - Automatic session expiration after 10 minutes of inactivity
    - Secure cleanup on logout (clears both session and encryption key)

    Session file contains (all encrypted):
    - user_id: User's database ID
    - username: Username
    - timestamp: Session creation/update time
    - encryption_key: User's derived encryption key (for password decryption)

    The encryption key is persisted in the encrypted session file to support
    separate CLI invocations while maintaining security through:
    - Fernet encryption of the entire session file
    - Restricted file permissions (should be 600)
    - Automatic cleanup on logout/expiration
    """

    # Session timeout in minutes
    SESSION_TIMEOUT_MINUTES = 10

    def __init__(self, session_file: str = ".session"):
        """Initialize session manager.

        Args:
            session_file: Name of session file (default: .session)
        """
        self.data_dir = get_data_dir()
        self.session_file_path = self.data_dir / session_file
        self.key_file_path = self.data_dir / ".enckey"

        # In-memory encryption key cache
        # Will be populated from session file if session exists
        self._encryption_key_cache: Optional[bytes] = None

        # Load session and restore encryption key if present
        self.session = self._load_session()

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

        Also restores the encryption key to memory if present in session file.

        Returns:
            Session data dict (without encryption_key field) if exists, None otherwise
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
            session_data = json.loads(decrypted_data.decode())

            # Restore encryption key to memory if present
            if "encryption_key" in session_data:
                import base64

                self._encryption_key_cache = base64.b64decode(
                    session_data["encryption_key"]
                )
                # Remove from session dict (keep in cache only)
                del session_data["encryption_key"]

            return session_data

        return None

    def _save_session(self):
        """Encrypt and save session to disk.

        Saves session data including the encryption key, all encrypted with Fernet.
        The encryption key is included to allow subsequent CLI invocations to
        access encrypted passwords during an active session.

        Security note:
        - Session file is encrypted with Fernet (symmetric encryption)
        - Session file should have restricted permissions (600)
        - Encryption key is cleared on logout or session expiration
        """
        if self.session is None:
            return

        # Creates an encryption key if not exists then retrieve it
        self._create_secret_key()
        secret_key = self._get_secret_key()
        fernet = Fernet(secret_key)

        # Update timestamp
        self.session["timestamp"] = datetime.now().isoformat()

        # Prepare session data including encryption key (if cached)
        session_data = self.session.copy()
        if self._encryption_key_cache is not None:
            # Store encryption key as base64 for JSON serialization
            import base64

            session_data["encryption_key"] = base64.b64encode(
                self._encryption_key_cache
            ).decode("utf-8")

        # Encrypt session (including encryption key)
        encrypted_session = fernet.encrypt(json.dumps(session_data).encode())

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
        all session data (including encryption key) to encrypted session file.

        Args:
            user_data: Dictionary containing:
                - user_id: User's database ID
                - username: Username
                - encryption_key: Derived encryption key (cached and persisted)
                - Other optional fields (not persisted)

        Security:
            - encryption_key is cached in memory for performance
            - Session file is encrypted with Fernet before writing to disk
            - Session file should have restricted permissions (600)
        """
        # Extract and cache encryption key
        if "encryption_key" in user_data:
            self._encryption_key_cache = user_data["encryption_key"]

        # Create session data
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
            - Key is encrypted in session file for multi-invocation support
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
