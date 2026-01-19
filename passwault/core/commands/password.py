"""Password management commands with encryption and authentication.

This module provides CLI commands for managing encrypted passwords including
save, load, update, delete, and password generation functionality.
"""

import re
from random import choice
from typing import Optional

from passwault.core.database.password_manager import PasswordRepository
from passwault.core.utils.decorators import require_auth
from passwault.core.utils.local_types import PasswaultError
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


@require_auth
def save_password(
    resource_name: str,
    password: str,
    session_manager: SessionManager,
    username: Optional[str] = None,
    website: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[str] = None,
) -> None:
    """Save a new encrypted password entry.

    Requires active authentication. Encrypts the password before storing
    in the database using the user's encryption key.

    Args:
        resource_name: Name/identifier for this password (e.g., "github")
        password: Plain-text password to encrypt and store
        username: Optional username associated with this password
        website: Optional website URL
        description: Optional description
        tags: Optional comma-separated tags
        session_manager: Session manager instance (injected by decorator)

    Example:
        >>> save_password("github", "mypass123", username="john", session_manager=sm)
        Password for 'github' saved successfully!
    """
    if not resource_name or not password:
        Logger.error("Resource name and password are required")
        return

    # Get user ID and encryption key from session
    user_id = session_manager.get_user_id()
    assert user_id is not None, "require_auth guarantees an active session"
    encryption_key = session_manager.get_encryption_key()
    assert encryption_key is not None, "require_auth guarantees encryption key"

    # Save password with encryption
    repo = PasswordRepository()
    try:
        repo.save_password(
            user_id=user_id,
            encryption_key=encryption_key,
            resource_name=resource_name,
            password=password,
            username=username,
            website=website,
            description=description,
            tags=tags,
        )
        Logger.info(f"Password for '{resource_name}' saved successfully!")
    except PasswaultError as e:
        Logger.error(f"Error saving password: {str(e)}")
        return


@require_auth
def load_password(
    session_manager: SessionManager,
    resource_name: Optional[str] = None,
    username: Optional[str] = None,
    all_passwords: bool = False,
) -> None:
    """Load and decrypt password(s).

    Requires active authentication. Can load a specific password by resource name,
    all passwords for a username, or all passwords.

    Args:
        resource_name: Resource name to load (if specified)
        username: Username to search for (if specified)
        all_passwords: If True, load all passwords for the user
        session_manager: Session manager instance (injected by decorator)

    Example:
        >>> load_password(resource_name="github", session_manager=sm)
        Resource: github
        Username: john
        Password: mypass123
        Website: https://github.com
    """
    user_id = session_manager.get_user_id()
    assert user_id is not None, "require_auth guarantees an active session"
    encryption_key = session_manager.get_encryption_key()
    assert encryption_key is not None, "require_auth guarantees encryption key"
    repo = PasswordRepository()

    try:
        # Load all passwords
        if all_passwords:
            passwords = repo.get_all_passwords(user_id, encryption_key)

            if not passwords:
                Logger.info("No passwords found")
                return

            Logger.info(f"\nFound {len(passwords)} password(s):\n")
            for pwd in passwords:
                _display_password_entry(pwd)

            return

        # Load by resource name
        if resource_name:
            pwd_data = repo.get_password_by_resource_name(
                user_id, encryption_key, resource_name
            )
            _display_password_entry(pwd_data)
            return

        # Load by username
        if username:
            passwords = repo.get_password_by_username(user_id, encryption_key, username)

            Logger.info(
                f"\nFound {len(passwords)} password(s) for username '{username}':\n"
            )
            for pwd in passwords:
                _display_password_entry(pwd)

            return

        Logger.error("Please specify --resource-name, --username, or --all")

    except PasswaultError as e:
        Logger.error(str(e))
        return


@require_auth
def update_password(
    resource_name: str,
    new_password: str,
    session_manager: SessionManager,
    username: Optional[str] = None,
    website: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[str] = None,
) -> None:
    """Update an existing password entry.

    Requires active authentication. Re-encrypts the password with the new value.

    Args:
        resource_name: Resource name to update
        new_password: New password to encrypt and store
        username: Optional new username
        website: Optional new website
        description: Optional new description
        tags: Optional new tags
        session_manager: Session manager instance (injected by decorator)

    Example:
        >>> update_password("github", "newpass456", session_manager=sm)
        Password for 'github' updated successfully!
    """
    if not resource_name or not new_password:
        Logger.error("Resource name and new password are required")
        return

    user_id = session_manager.get_user_id()
    assert user_id is not None, "require_auth guarantees an active session"
    encryption_key = session_manager.get_encryption_key()
    assert encryption_key is not None, "require_auth guarantees encryption key"

    repo = PasswordRepository()
    try:
        repo.update_password(
            user_id=user_id,
            encryption_key=encryption_key,
            resource_name=resource_name,
            new_password=new_password,
            username=username,
            website=website,
            description=description,
            tags=tags,
        )
        Logger.info(f"Password for '{resource_name}' updated successfully!")
    except PasswaultError as e:
        Logger.error(f"Error updating password: {str(e)}")
        return


@require_auth
def delete_password(
    resource_name: str,
    session_manager: SessionManager,
) -> None:
    """Delete a password entry.

    Requires active authentication. Permanently removes the password from the database.

    Args:
        resource_name: Resource name to delete
        session_manager: Session manager instance (injected by decorator)

    Example:
        >>> delete_password("github", session_manager=sm)
        Password for 'github' deleted successfully!
    """
    if not resource_name:
        Logger.error("Resource name is required")
        return

    user_id = session_manager.get_user_id()
    assert user_id is not None, "require_auth guarantees an session with user_id"

    repo = PasswordRepository()
    try:
        repo.delete_password(user_id, resource_name)
        Logger.info(f"Password for '{resource_name}' deleted successfully!")
    except PasswaultError as e:
        Logger.error(f"Error deleting password: {str(e)}")
        return


def generate_password(
    password_length: int = 16,
    has_symbols: bool = True,
    has_digits: bool = True,
    has_uppercase: bool = True,
) -> None:
    """Generate a random secure password.

    Does not require authentication. Generates password based on specified criteria.

    Args:
        password_length: Length of password to generate (default: 16)
        has_symbols: Include symbols (default: True)
        has_digits: Include digits (default: True)
        has_uppercase: Include uppercase letters (default: True)

    Example:
        >>> generate_password(password_length=20, has_symbols=True)
        Generated password: Kx9#mP2$qL7&nR4!jF8@
    """
    MAX_ITER = 10
    SYMBOLS_RANGE = [33, 38]
    DIGITS_RANGE = [48, 57]
    UPPERCASE_RANGE = [65, 90]
    LOWERCASE_RANGE = [97, 122]

    # Validates the password
    def _validate(password: str) -> bool:
        if has_symbols:
            if not bool(re.search(r"[^a-zA-Z0-9\s]", password)):
                return False
        if has_digits:
            if not any(char.isdigit() for char in password):
                return False
        if has_uppercase:
            if not any(char.isupper() for char in password):
                return False

        return True

    count = 0
    while True:
        pool = [i for i in range(LOWERCASE_RANGE[0], LOWERCASE_RANGE[1] + 1)]

        if has_symbols:
            pool.extend([i for i in range(SYMBOLS_RANGE[0], SYMBOLS_RANGE[1] + 1)])

        if has_digits:
            pool.extend([i for i in range(DIGITS_RANGE[0], DIGITS_RANGE[1] + 1)])

        if has_uppercase:
            pool.extend([i for i in range(UPPERCASE_RANGE[0], UPPERCASE_RANGE[1] + 1)])

        password = "".join([chr(choice(pool)) for _ in range(password_length)])

        if _validate(password):
            break

        # Failsafe for infinite loop
        count += 1
        if count >= MAX_ITER:
            Logger.error("Error generating password")
            return

    Logger.info(f"Generated password: {password}")


def _display_password_entry(entry: dict) -> None:
    """Display a password entry in formatted output.

    Args:
        entry: Password entry dictionary
    """
    print("\n" + "=" * 60)
    print(f"Resource: {entry['resource_name']}")
    if entry.get("username"):
        print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")
    if entry.get("website"):
        print(f"Website: {entry['website']}")
    if entry.get("description"):
        print(f"Description: {entry['description']}")
    if entry.get("tags"):
        print(f"Tags: {entry['tags']}")
    print(f"Created: {entry['created_at']}")
    print(f"Updated: {entry['updated_at']}")
    print("=" * 60)
