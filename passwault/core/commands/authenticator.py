"""Authentication commands for user registration, login, and logout.

This module implements the authentication flow for the Passwault password manager,
including user registration, login with master password, and secure logout.
"""

from typing import Optional

from passwault.core.database.user_repository import UserRepository
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask
from passwault.core.utils.session_manager import SessionManager


def register(
    username: str,
    password: Optional[str],
    email: Optional[str],
    session_manager: SessionManager,
) -> None:
    """Register a new user account.

    Creates a new user with the provided credentials. If password is not provided,
    prompts the user to enter it securely with masking.

    Args:
        username: Desired username (must be unique)
        password: Master password (if None, will prompt)
        email: Optional email address
        session_manager: Session manager instance (not used during registration)

    Returns:
        None (prints success/error messages)

    Example:
        >>> register("john", "SecurePass123!", "john@example.com", session_manager)
        User 'john' registered successfully!
        You can now login with: passwault auth login -u john
    """
    # Prompt for password if not provided
    if password is None:
        Logger.info("Enter master password (will be hidden):")
        password = get_password_with_mask()

        if not password:
            Logger.error("Password cannot be empty")
            return

        Logger.info("Confirm master password:")
        password_confirm = get_password_with_mask()

        if password != password_confirm:
            Logger.error("Passwords do not match")
            return

    # Check if username already exists
    user_repo = UserRepository()
    username_check = user_repo.check_username_exists(username)

    if not username_check.ok:
        Logger.error(f"Error checking username: {username_check.result}")
        return

    if username_check.result is True:
        Logger.error(
            f"Username '{username}' is already taken. Please choose another username."
        )
        return

    # Register the user
    result = user_repo.register(username, password, email)

    if not result.ok:
        Logger.error(f"Registration failed: {result.result}")
        return

    user_id = result.result
    Logger.info(f"User '{username}' registered successfully! (ID: {user_id})")
    Logger.info(f"You can now login with: passwault auth login -u {username}")


def login(
    username: str, password: Optional[str], session_manager: SessionManager
) -> None:
    """Authenticate user and create session.

    Verifies credentials and creates an authenticated session with encryption
    key caching. The encryption key is stored in memory only and cleared on
    logout or session expiration.

    Args:
        username: Username to authenticate
        password: Master password (if None, will prompt)
        session_manager: Session manager instance for creating session

    Returns:
        None (prints success/error messages)

    Example:
        >>> login("john", "SecurePass123!", session_manager)
        Login successful! Welcome back, john.
    """
    # Prompt for password if not provided
    if password is None:
        Logger.info("Enter master password (will be hidden):")
        password = get_password_with_mask()

        if not password:
            Logger.error("Password cannot be empty")
            return

    # Authenticate user
    user_repo = UserRepository()
    auth_result = user_repo.authenticate(username, password)

    if not auth_result.ok:
        Logger.error(f"Login failed: {auth_result.result}")
        return

    # Extract user data and encryption key
    user_data = auth_result.result

    # Create session with encryption key caching
    session_manager.create_session(user_data)

    Logger.info(f"Login successful! Welcome back, {username}.")
    Logger.info(
        f"Your session will expire after {session_manager.SESSION_TIMEOUT_MINUTES} minutes of inactivity."
    )


def logout(session_manager: SessionManager) -> None:
    """Log out current user and clear session.

    Clears the user session, removes encryption keys from memory, and deletes
    the session file from disk.

    Args:
        session_manager: Session manager instance

    Returns:
        None (prints success/error messages)

    Example:
        >>> logout(session_manager)
        Logged out successfully. Your session and encryption keys have been cleared.
    """
    # Check if user is logged in
    if not session_manager.is_logged_in():
        Logger.info("No active session to logout from.")
        return

    # Get username before logout
    username = session_manager.get_username()

    # Perform logout (clears session and encryption key)
    session_manager.logout()

    Logger.info(f"Logged out successfully. Goodbye, {username}!")
    Logger.info("Your session and encryption keys have been cleared from memory.")
