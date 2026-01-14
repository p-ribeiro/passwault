"""User repository for authentication and user management.

This module handles all user-related database operations including
registration, authentication, and user lookups.
"""

from typing import Optional, Dict, Any

from sqlalchemy.exc import IntegrityError

from passwault.core.database import models
from passwault.core.database.models import User
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.local_types import Response, Success, Fail


class UserRepository:
    """Repository for user management and authentication.

    Handles user registration, authentication, and related operations.
    Uses CryptoService for password hashing and key derivation.
    """

    def __init__(self):
        """Initialize the user repository with crypto service."""
        self.crypto = CryptoService()

    def register(
        self, username: str, master_password: str, email: Optional[str] = None
    ) -> Response[int]:
        """Register a new user with a master password.

        Creates a new user account with:
        - bcrypt-hashed master password for authentication
        - Random salt for encryption key derivation
        - Default KDF parameters (PBKDF2, 600k iterations)

        Args:
            username: Unique username for the account
            master_password: Master password (will be hashed)
            email: Optional email address

        Returns:
            Response[int]: Success with user_id, or Fail with error message

        Example:
            >>> repo = UserRepository()
            >>> result = repo.register("john", "SecurePass123!", "john@example.com")
            >>> if result.ok:
            ...     print(f"User registered with ID: {result.result}")
        """
        session = models.SessionLocal()
        try:
            # Generate salt for encryption key derivation
            salt = self.crypto.generate_salt()

            # Hash master password for authentication
            password_hash = self.crypto.hash_master_password(master_password)

            # Create new user record
            new_user = User(
                username=username,
                email=email,
                master_password_hash=password_hash,
                salt=salt,
                kdf_algorithm="PBKDF2",
                kdf_iterations=CryptoService.DEFAULT_KDF_ITERATIONS,
            )

            session.add(new_user)
            session.commit()
            session.refresh(new_user)

            return Success(new_user.id)

        except IntegrityError as e:
            session.rollback()
            error_msg = str(e.orig) if hasattr(e, "orig") else str(e)
            if "UNIQUE constraint" in error_msg or "unique" in error_msg.lower():
                if "username" in error_msg.lower():
                    return Fail("Username already exists")
                elif "email" in error_msg.lower():
                    return Fail("Email already exists")
                else:
                    return Fail("Username or email already exists")
            return Fail(f"Database integrity error: {error_msg}")

        except Exception as e:
            session.rollback()
            return Fail(f"Error during registration: {str(e)}")

        finally:
            session.close()

    def authenticate(
        self, username: str, master_password: str
    ) -> Response[Dict[str, Any]]:
        """Authenticate a user and derive their encryption key.

        Verifies the master password and derives the encryption key
        that will be used to encrypt/decrypt stored passwords.

        Args:
            username: Username to authenticate
            master_password: Master password to verify

        Returns:
            Response[Dict]: Success with dict containing:
                - user_id: The user's ID
                - username: The username
                - encryption_key: Derived encryption key (32 bytes)
                - salt: The user's salt
                - kdf_iterations: KDF iteration count
            Or Fail with error message

        Example:
            >>> repo = UserRepository()
            >>> result = repo.authenticate("john", "SecurePass123!")
            >>> if result.ok:
            ...     user_data = result.result
            ...     encryption_key = user_data["encryption_key"]
        """
        session = models.SessionLocal()
        try:
            # Query user by username
            user = session.query(User).filter_by(username=username).first()

            if not user:
                return Fail("User not found")

            # Verify master password
            if not self.crypto.verify_master_password(
                master_password, user.master_password_hash
            ):
                return Fail("Invalid password")

            # Derive encryption key from master password
            encryption_key = self.crypto.derive_encryption_key(
                master_password, user.salt, user.kdf_iterations
            )

            # Update last login timestamp
            from sqlalchemy.sql import func

            user.last_login = func.now()
            session.commit()

            # Return user data with encryption key
            return Success(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "encryption_key": encryption_key,
                    "salt": user.salt,
                    "kdf_iterations": user.kdf_iterations,
                }
            )

        except Exception as e:
            session.rollback()
            return Fail(f"Error during authentication: {str(e)}")

        finally:
            session.close()

    def get_user_by_id(self, user_id: int) -> Response[Dict[str, Any]]:
        """Get user information by user ID.

        Args:
            user_id: The user's ID

        Returns:
            Response[Dict]: Success with user data (without sensitive info)
                or Fail with error message
        """
        session = models.SessionLocal()
        try:
            user = session.query(User).filter_by(id=user_id).first()

            if not user:
                return Fail("User not found")

            return Success(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "created_at": user.created_at,
                    "last_login": user.last_login,
                }
            )

        except Exception as e:
            return Fail(f"Error retrieving user: {str(e)}")

        finally:
            session.close()

    def get_user_by_username(self, username: str) -> Response[Dict[str, Any]]:
        """Get user information by username.

        Args:
            username: The username to look up

        Returns:
            Response[Dict]: Success with user data (without sensitive info)
                or Fail with error message
        """
        session = models.SessionLocal()
        try:
            user = session.query(User).filter_by(username=username).first()

            if not user:
                return Fail("User not found")

            return Success(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "created_at": user.created_at,
                    "last_login": user.last_login,
                }
            )

        except Exception as e:
            return Fail(f"Error retrieving user: {str(e)}")

        finally:
            session.close()

    def check_username_exists(self, username: str) -> Response[bool]:
        """Check if a username already exists.

        Args:
            username: Username to check

        Returns:
            Response[bool]: Success with True if exists, False otherwise
        """
        session = models.SessionLocal()
        try:
            exists = (
                session.query(User).filter_by(username=username).first() is not None
            )
            return Success(exists)

        except Exception as e:
            return Fail(f"Error checking username: {str(e)}")

        finally:
            session.close()
