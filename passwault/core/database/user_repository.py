"""User repository for authentication and user management.

This module handles all user-related database operations including
registration, authentication, and user lookups.
"""

from typing import Optional, Dict, Any

from sqlalchemy.exc import IntegrityError

from passwault.core.database import models
from passwault.core.database.models import User
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.local_types import (
    AuthenticationError,
    DatabaseError,
    ResourceNotFoundError,
    ResourceExistsError,
)


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
    ) -> int:
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
            int: The user ID

        Raises:
            ResourceExistsError: If username or email already exists
            DatabaseError: If database operation fails

        Example:
            >>> repo = UserRepository()
            >>> user_id = repo.register("john", "SecurePass123!", "john@example.com")
            >>> print(f"User registered with ID: {user_id}")
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

            return new_user.id

        except IntegrityError as e:
            session.rollback()
            error_msg = str(e.orig) if hasattr(e, "orig") else str(e)
            if "UNIQUE constraint" in error_msg or "unique" in error_msg.lower():
                if "username" in error_msg.lower():
                    raise ResourceExistsError("Username already exists")
                elif "email" in error_msg.lower():
                    raise ResourceExistsError("Email already exists")
                else:
                    raise ResourceExistsError("Username or email already exists")
            raise DatabaseError(f"Database integrity error: {error_msg}")

        except ResourceExistsError:
            raise

        except Exception as e:
            session.rollback()
            raise DatabaseError(f"Error during registration: {str(e)}")

        finally:
            session.close()

    def authenticate(self, username: str, master_password: str) -> Dict[str, Any]:
        """Authenticate a user and derive their encryption key.

        Verifies the master password and derives the encryption key
        that will be used to encrypt/decrypt stored passwords.

        Args:
            username: Username to authenticate
            master_password: Master password to verify

        Returns:
            Dict: User data containing:
                - user_id: The user's ID
                - username: The username
                - encryption_key: Derived encryption key (32 bytes)
                - salt: The user's salt
                - kdf_iterations: KDF iteration count

        Raises:
            AuthenticationError: If user not found or invalid password
            DatabaseError: If database operation fails

        Example:
            >>> repo = UserRepository()
            >>> user_data = repo.authenticate("john", "SecurePass123!")
            >>> encryption_key = user_data["encryption_key"]
        """
        session = models.SessionLocal()
        try:
            # Query user by username
            user = session.query(User).filter_by(username=username).first()

            if not user:
                raise AuthenticationError("User not found")

            # Verify master password
            if not self.crypto.verify_master_password(
                master_password, user.master_password_hash
            ):
                raise AuthenticationError("Invalid password")

            # Derive encryption key from master password
            encryption_key = self.crypto.derive_encryption_key(
                master_password, user.salt, user.kdf_iterations
            )

            # Update last login timestamp
            from sqlalchemy.sql import func

            user.last_login = func.now()
            session.commit()

            # Return user data with encryption key
            return {
                "user_id": user.id,
                "username": user.username,
                "encryption_key": encryption_key,
                "salt": user.salt,
                "kdf_iterations": user.kdf_iterations,
            }

        except AuthenticationError:
            raise

        except Exception as e:
            session.rollback()
            raise DatabaseError(f"Error during authentication: {str(e)}")

        finally:
            session.close()

    def get_user_by_id(self, user_id: int) -> Dict[str, Any]:
        """Get user information by user ID.

        Args:
            user_id: The user's ID

        Returns:
            Dict: User data (without sensitive info)

        Raises:
            ResourceNotFoundError: If user not found
            DatabaseError: If database operation fails
        """
        session = models.SessionLocal()
        try:
            user = session.query(User).filter_by(id=user_id).first()

            if not user:
                raise ResourceNotFoundError("User not found")

            return {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at,
                "last_login": user.last_login,
            }

        except ResourceNotFoundError:
            raise

        except Exception as e:
            raise DatabaseError(f"Error retrieving user: {str(e)}")

        finally:
            session.close()

    def get_user_by_username(self, username: str) -> Dict[str, Any]:
        """Get user information by username.

        Args:
            username: The username to look up

        Returns:
            Dict: User data (without sensitive info)

        Raises:
            ResourceNotFoundError: If user not found
            DatabaseError: If database operation fails
        """
        session = models.SessionLocal()
        try:
            user = session.query(User).filter_by(username=username).first()

            if not user:
                raise ResourceNotFoundError("User not found")

            return {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at,
                "last_login": user.last_login,
            }

        except ResourceNotFoundError:
            raise

        except Exception as e:
            raise DatabaseError(f"Error retrieving user: {str(e)}")

        finally:
            session.close()

    def check_username_exists(self, username: str) -> bool:
        """Check if a username already exists.

        Args:
            username: Username to check

        Returns:
            bool: True if exists, False otherwise

        Raises:
            DatabaseError: If database operation fails
        """
        session = models.SessionLocal()
        try:
            exists = (
                session.query(User).filter_by(username=username).first() is not None
            )
            return exists

        except Exception as e:
            raise DatabaseError(f"Error checking username: {str(e)}")

        finally:
            session.close()
