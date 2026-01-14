"""Authentication decorators for protecting password operations.

This module provides decorators to ensure users are authenticated before
executing sensitive operations like saving or loading passwords.
"""

from functools import wraps
from typing import Callable, Any

from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


def require_auth(func: Callable) -> Callable:
    """Decorator to require active authentication before executing function.

    This decorator checks if:
    1. User has an active session (not expired)
    2. Encryption key is available in memory

    If either check fails, the function returns None and logs an error message.

    Usage:
        @require_auth
        def save_password(password_name, password, session_manager):
            # This code only runs if user is authenticated
            pass

    Args:
        func: Function to wrap (must accept session_manager as last argument)

    Returns:
        Wrapped function that checks authentication before execution

    Note:
        The decorated function must accept a SessionManager instance as its
        last positional or keyword argument named 'session_manager'.
    """

    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        # Extract session_manager from args or kwargs
        session_manager = None

        # Check if session_manager is in kwargs
        if "session_manager" in kwargs:
            session_manager = kwargs["session_manager"]
        # Check if it's the last positional argument
        elif args:
            # Look for SessionManager instance in args
            for arg in args:
                if isinstance(arg, SessionManager):
                    session_manager = arg
                    break

        # Validate session_manager was found
        if session_manager is None:
            Logger.error(
                "Authentication decorator error: session_manager not found in arguments"
            )
            return None

        if not isinstance(session_manager, SessionManager):
            Logger.error(
                "Authentication decorator error: session_manager is not a SessionManager instance"
            )
            return None

        # Check if user is logged in
        if not session_manager.is_logged_in():
            Logger.info("Authentication required. Please login first.")
            Logger.info("Use: passwault auth login -u <username>")
            return None

        # Check if encryption key is available
        encryption_key = session_manager.get_encryption_key()
        if encryption_key is None:
            Logger.info("Session expired. Please login again to access passwords.")
            Logger.info("Use: passwault auth login -u <username>")
            return None

        # All checks passed, execute the function
        return func(*args, **kwargs)

    return wrapper
