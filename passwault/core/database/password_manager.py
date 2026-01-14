"""Password repository for encrypted password storage and retrieval.

This module handles all password-related database operations with encryption support.
All passwords are encrypted using AES-256-GCM before storage.
"""

from typing import Optional, List, Dict, Any
from sqlalchemy.exc import IntegrityError

from passwault.core.database import models
from passwault.core.database.models import PasswordManager
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.local_types import Response, Success, Fail


class PasswordRepository:
    """Repository for password management with encryption.

    All passwords are encrypted with AES-256-GCM before storage.
    Each user's passwords are isolated and can only be accessed with
    their encryption key.
    """

    def __init__(self):
        """Initialize password repository."""
        self.crypto = CryptoService()

    def save_password(
        self,
        user_id: int,
        encryption_key: bytes,
        resource_name: str,
        password: str,
        username: Optional[str] = None,
        website: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Response[int]:
        """Save a new password entry with encryption.

        Encrypts the password using AES-256-GCM before storing in database.
        Each user can have only one password per resource_name.

        Args:
            user_id: User's database ID
            encryption_key: User's encryption key (32 bytes)
            resource_name: Name/identifier for this password (e.g., "github")
            password: Plain-text password to encrypt and store
            username: Optional username associated with this password
            website: Optional website URL
            description: Optional description
            tags: Optional comma-separated tags

        Returns:
            Response[int]: Success with password entry ID, or Fail with error message

        Example:
            >>> repo = PasswordRepository()
            >>> result = repo.save_password(
            ...     user_id=1,
            ...     encryption_key=b"...",
            ...     resource_name="github",
            ...     password="mypassword123"
            ... )
            >>> if result.ok:
            ...     print(f"Password saved with ID: {result.result}")
        """
        session = models.SessionLocal()
        try:
            # Encrypt password
            ciphertext, nonce = self.crypto.encrypt_password(password, encryption_key)

            # Create password entry
            password_entry = PasswordManager(
                user_id=user_id,
                resource_name=resource_name,
                encrypted_password=ciphertext,
                nonce=nonce,
                username=username,
                website=website,
                description=description,
                tags=tags,
            )

            session.add(password_entry)
            session.commit()
            session.refresh(password_entry)

            return Success(password_entry.id)

        except IntegrityError:
            session.rollback()
            return Fail(
                f"Password for '{resource_name}' already exists. "
                "Use update operation to change it."
            )

        except Exception as e:
            session.rollback()
            return Fail(f"Error saving password: {str(e)}")

        finally:
            session.close()

    def get_password_by_resource_name(
        self, user_id: int, encryption_key: bytes, resource_name: str
    ) -> Response[Dict[str, Any]]:
        """Retrieve and decrypt password by resource name.

        Args:
            user_id: User's database ID
            encryption_key: User's encryption key for decryption
            resource_name: Resource name to search for

        Returns:
            Response[Dict]: Success with password data (including decrypted password),
                or Fail with error message

        Example:
            >>> result = repo.get_password_by_resource_name(1, key, "github")
            >>> if result.ok:
            ...     print(f"Username: {result.result['username']}")
            ...     print(f"Password: {result.result['password']}")
        """
        session = models.SessionLocal()
        try:
            entry = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name=resource_name)
                .first()
            )

            if not entry:
                return Fail(f"No password found for resource '{resource_name}'")

            # Decrypt password
            try:
                decrypted_password = self.crypto.decrypt_password(
                    entry.encrypted_password, entry.nonce, encryption_key
                )
            except Exception as decrypt_error:
                return Fail(
                    f"Error decrypting password: {str(decrypt_error)}. "
                    "Your encryption key may be incorrect."
                )

            return Success(
                {
                    "id": entry.id,
                    "resource_name": entry.resource_name,
                    "username": entry.username,
                    "password": decrypted_password,
                    "website": entry.website,
                    "description": entry.description,
                    "tags": entry.tags,
                    "created_at": entry.created_at,
                    "updated_at": entry.updated_at,
                }
            )

        except Exception as e:
            return Fail(f"Error retrieving password: {str(e)}")

        finally:
            session.close()

    def get_password_by_username(
        self, user_id: int, encryption_key: bytes, username: str
    ) -> Response[List[Dict[str, Any]]]:
        """Retrieve and decrypt passwords by username.

        Multiple passwords may have the same username, so returns a list.

        Args:
            user_id: User's database ID
            encryption_key: User's encryption key for decryption
            username: Username to search for

        Returns:
            Response[List[Dict]]: Success with list of password data,
                or Fail with error message
        """
        session = models.SessionLocal()
        try:
            entries = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, username=username)
                .all()
            )

            if not entries:
                return Fail(f"No passwords found for username '{username}'")

            results = []
            for entry in entries:
                try:
                    decrypted_password = self.crypto.decrypt_password(
                        entry.encrypted_password, entry.nonce, encryption_key
                    )
                    results.append(
                        {
                            "id": entry.id,
                            "resource_name": entry.resource_name,
                            "username": entry.username,
                            "password": decrypted_password,
                            "website": entry.website,
                            "description": entry.description,
                            "tags": entry.tags,
                            "created_at": entry.created_at,
                            "updated_at": entry.updated_at,
                        }
                    )
                except Exception:
                    # Skip entries that can't be decrypted
                    continue

            if not results:
                return Fail(f"Could not decrypt any passwords for username '{username}'")

            return Success(results)

        except Exception as e:
            return Fail(f"Error retrieving passwords: {str(e)}")

        finally:
            session.close()

    def get_all_passwords(
        self, user_id: int, encryption_key: bytes
    ) -> Response[List[Dict[str, Any]]]:
        """Retrieve and decrypt all passwords for a user.

        Args:
            user_id: User's database ID
            encryption_key: User's encryption key for decryption

        Returns:
            Response[List[Dict]]: Success with list of all password data,
                or Fail with error message
        """
        session = models.SessionLocal()
        try:
            entries = session.query(PasswordManager).filter_by(user_id=user_id).all()

            if not entries:
                return Fail("No passwords found")

            results = []
            for entry in entries:
                try:
                    decrypted_password = self.crypto.decrypt_password(
                        entry.encrypted_password, entry.nonce, encryption_key
                    )
                    results.append(
                        {
                            "id": entry.id,
                            "resource_name": entry.resource_name,
                            "username": entry.username,
                            "password": decrypted_password,
                            "website": entry.website,
                            "description": entry.description,
                            "tags": entry.tags,
                            "created_at": entry.created_at,
                            "updated_at": entry.updated_at,
                        }
                    )
                except Exception:
                    # Skip entries that can't be decrypted
                    continue

            if not results:
                return Fail("Could not decrypt any passwords")

            return Success(results)

        except Exception as e:
            return Fail(f"Error retrieving passwords: {str(e)}")

        finally:
            session.close()

    def update_password(
        self,
        user_id: int,
        encryption_key: bytes,
        resource_name: str,
        new_password: str,
        username: Optional[str] = None,
        website: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Response[bool]:
        """Update an existing password entry.

        Args:
            user_id: User's database ID
            encryption_key: User's encryption key
            resource_name: Resource name to update
            new_password: New password to encrypt and store
            username: Optional new username
            website: Optional new website
            description: Optional new description
            tags: Optional new tags

        Returns:
            Response[bool]: Success(True) if updated, Fail with error message otherwise
        """
        session = models.SessionLocal()
        try:
            entry = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name=resource_name)
                .first()
            )

            if not entry:
                return Fail(f"No password found for resource '{resource_name}'")

            # Encrypt new password
            ciphertext, nonce = self.crypto.encrypt_password(
                new_password, encryption_key
            )

            # Update entry
            entry.encrypted_password = ciphertext
            entry.nonce = nonce

            if username is not None:
                entry.username = username
            if website is not None:
                entry.website = website
            if description is not None:
                entry.description = description
            if tags is not None:
                entry.tags = tags

            session.commit()
            return Success(True)

        except Exception as e:
            session.rollback()
            return Fail(f"Error updating password: {str(e)}")

        finally:
            session.close()

    def delete_password(
        self, user_id: int, resource_name: str
    ) -> Response[bool]:
        """Delete a password entry.

        Args:
            user_id: User's database ID
            resource_name: Resource name to delete

        Returns:
            Response[bool]: Success(True) if deleted, Fail with error message otherwise
        """
        session = models.SessionLocal()
        try:
            entry = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name=resource_name)
                .first()
            )

            if not entry:
                return Fail(f"No password found for resource '{resource_name}'")

            session.delete(entry)
            session.commit()
            return Success(True)

        except Exception as e:
            session.rollback()
            return Fail(f"Error deleting password: {str(e)}")

        finally:
            session.close()

    def check_resource_exists(self, user_id: int, resource_name: str) -> Response[bool]:
        """Check if a password exists for a resource.

        Args:
            user_id: User's database ID
            resource_name: Resource name to check

        Returns:
            Response[bool]: Success with True if exists, False otherwise
        """
        session = models.SessionLocal()
        try:
            exists = (
                session.query(PasswordManager)
                .filter_by(user_id=user_id, resource_name=resource_name)
                .first()
                is not None
            )
            return Success(exists)

        except Exception as e:
            return Fail(f"Error checking resource: {str(e)}")

        finally:
            session.close()
