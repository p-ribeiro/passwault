"""Authentication commands for user registration, login, and logout.

This module implements the authentication flow for the Passwault password manager,
including user registration, login with master password, and secure logout.
"""

from typing import Optional

from passwault.core.database.password_manager import PasswordRepository
from passwault.core.database.user_repository import UserRepository
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.decorators import require_auth
from passwault.core.utils.local_types import PasswaultError
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask
from passwault.core.utils.session_manager import SessionManager
from passwault.core.database import models
from passwault.core.database.models import User


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
    try:
        username_exists = user_repo.check_username_exists(username)

        if username_exists:
            Logger.error(
                f"Username '{username}' is already taken. Please choose another username."
            )
            return

        # Register the user
        user_id = user_repo.register(username, password, email)

        Logger.info(f"User '{username}' registered successfully! (ID: {user_id})")
        Logger.info(f"You can now login with: passwault auth login -u {username}")

    except PasswaultError as e:
        Logger.error(f"Registration failed: {str(e)}")
        return


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
    try:
        user_data = user_repo.authenticate(username, password)

        # Create session with encryption key caching
        session_manager.create_session(user_data)

        Logger.info(f"Login successful! Welcome back, {username}.")
        Logger.info(
            f"Your session will expire after {session_manager.SESSION_TIMEOUT_MINUTES} minutes of inactivity."
        )

    except PasswaultError as e:
        Logger.error(f"Login failed: {str(e)}")
        return


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


@require_auth
def change_master_password(
    old_password: Optional[str],
    new_password: Optional[str],
    session_manager: SessionManager,
) -> None:
    """Change the user's master password and re-encrypt all passwords.

    This operation:
    1. Verifies the old master password
    2. Loads all user's passwords and decrypts them with the old key
    3. Generates a new salt and derives a new encryption key
    4. Re-encrypts all passwords with the new encryption key
    5. Updates the user record with new password hash and salt
    6. Updates the session with the new encryption key

    Args:
        old_password: Current master password (if None, will prompt)
        new_password: New master password (if None, will prompt)
        session_manager: Session manager instance (injected by decorator)

    Returns:
        None (prints success/error messages)

    Example:
        >>> change_master_password(None, None, session_manager)
        Enter current master password: ********
        Enter new master password: ********
        Confirm new master password: ********
        Re-encrypting 10 password(s)...
        Master password changed successfully!

    Warning:
        This is a critical operation. If it fails midway, passwords may become
        inaccessible. The operation is performed in a database transaction
        to minimize this risk.
    """
    # Get current user info
    user_id = session_manager.get_user_id()
    assert user_id is not None, "require_auth guarantees an active session"
    username = session_manager.get_username()
    assert username is not None, "require_auth guarantees an username"
    current_encryption_key = session_manager.get_encryption_key()
    assert current_encryption_key is not None, "require_auth guarantees encryption key"

    # Prompt for old password if not provided
    if old_password is None:
        Logger.info("Enter current master password (will be hidden):")
        old_password = get_password_with_mask()

        if not old_password:
            Logger.error("Password cannot be empty")
            return

    # Verify old password
    user_repo = UserRepository()
    try:
        user_data = user_repo.authenticate(username, old_password)
        old_encryption_key = user_data["encryption_key"]

        if old_encryption_key != current_encryption_key:
            Logger.error("Encryption key mismatch. Please logout and login again.")
            return

    except PasswaultError:
        Logger.error("Current password is incorrect")
        return

    # Prompt for new password if not provided
    if new_password is None:
        Logger.info("Enter new master password (will be hidden):")
        new_password = get_password_with_mask()

        if not new_password:
            Logger.error("New password cannot be empty")
            return

        Logger.info("Confirm new master password:")
        password_confirm = get_password_with_mask()

        if new_password != password_confirm:
            Logger.error("Passwords do not match")
            return

    # Validate new password is different
    if old_password == new_password:
        Logger.error("New password must be different from current password")
        return

    # Load all passwords and decrypt them
    password_repo = PasswordRepository()
    try:
        passwords = password_repo.get_all_passwords(user_id, old_encryption_key)
        Logger.info(f"\nRe-encrypting {len(passwords)} password(s)...")
    except PasswaultError as e:
        Logger.error(f"Error loading passwords: {str(e)}")
        return

    # Generate new salt and encryption key
    crypto = CryptoService()
    new_salt = crypto.generate_salt()
    new_encryption_key = crypto.derive_encryption_key(
        new_password, new_salt, CryptoService.DEFAULT_KDF_ITERATIONS
    )
    new_password_hash = crypto.hash_master_password(new_password)

    # Start database transaction to update everything atomically
    session = models.SessionLocal()
    try:
        # Get user record
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            Logger.error("User not found in database")
            return

        # Update user record with new credentials
        user.master_password_hash = new_password_hash
        user.salt = new_salt
        user.kdf_iterations = CryptoService.DEFAULT_KDF_ITERATIONS

        # Re-encrypt all passwords
        for pwd_data in passwords:
            # Get the password entry from database
            from passwault.core.database.models import PasswordManager

            pwd_entry = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name=pwd_data["resource_name"])
                .first()
            )

            if pwd_entry:
                # Re-encrypt the password with new key
                plaintext_password = pwd_data["password"]
                ciphertext, nonce = crypto.encrypt_password(
                    plaintext_password, new_encryption_key
                )

                # Update the entry
                pwd_entry.encrypted_password = ciphertext
                pwd_entry.nonce = nonce

        # Commit all changes
        session.commit()

        # Update session with new encryption key
        user_data = {
            "user_id": user_id,
            "username": username,
            "encryption_key": new_encryption_key,
        }
        session_manager.create_session(user_data)

        Logger.info("\n✓ Master password changed successfully!")
        Logger.info(f"  - Re-encrypted {len(passwords)} password(s)")
        Logger.info("  - Session updated with new encryption key")
        Logger.info(
            "  - Please remember your new master password - it cannot be recovered!"
        )

    except Exception as e:
        session.rollback()
        Logger.error(f"Error changing master password: {str(e)}")
        Logger.error(
            "Operation cancelled. Your passwords remain encrypted with the old key."
        )
        return

    finally:
        session.close()
