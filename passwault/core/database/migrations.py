"""Database migration utilities for Passwault.

This module handles migration from plain-text password storage (v1)
to encrypted password storage with multi-user support (v2).

Migration Flow:
1. Detect if old schema exists (password_manager table without users table)
2. Prompt user to register (becomes migration owner)
3. Encrypt all existing passwords with new encryption key
4. Assign all passwords to the new user
5. Commit changes
"""

from typing import Optional

from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from passwault.core.database.models import Base, PasswordManager, User, engine, SessionLocal
from passwault.core.database.user_repository import UserRepository
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.local_types import Response, Success, Fail
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask


def check_migration_needed() -> Response[bool]:
    """Check if database migration is needed.

    Migration is needed when:
    1. password_manager table exists (has old data)
    2. users table doesn't exist OR is empty (no new schema users)
    3. password_manager has entries without user_id or with plain-text passwords

    Returns:
        Response[bool]: Success(True) if migration needed, Success(False) otherwise
    """
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        # If password_manager doesn't exist, no migration needed (fresh install)
        if "password_manager" not in tables:
            return Success(False)

        # Check if password_manager has the new schema columns
        columns = [col["name"] for col in inspector.get_columns("password_manager")]

        # If users table doesn't exist AND password_manager exists, need migration
        if "users" not in tables:
            Logger.info("Old schema detected (no users table)")
            return Success(True)

        # If encrypted_password or nonce columns don't exist, need migration
        if "encrypted_password" not in columns or "nonce" not in columns:
            Logger.info("Old schema detected (missing encrypted_password or nonce columns)")
            return Success(True)

        # Check if there are passwords in old format (user_id is NULL or 0)
        session = SessionLocal()
        try:
            # Check if password_manager has any data
            result = session.execute(text("SELECT COUNT(*) FROM password_manager"))
            password_count = result.scalar()

            # If no passwords, no migration needed
            if password_count == 0:
                return Success(False)

            # Try to query for passwords without proper user_id
            result = session.execute(
                text("SELECT COUNT(*) FROM password_manager WHERE user_id IS NULL OR user_id = 0")
            )
            orphaned_count = result.scalar()

            if orphaned_count > 0:
                Logger.info(f"Found {orphaned_count} passwords without user assignment")
                return Success(True)

            # Check if users table is empty but passwords exist
            result = session.execute(text("SELECT COUNT(*) FROM users"))
            user_count = result.scalar()

            if user_count == 0:
                Logger.info(f"Found {password_count} passwords but no users")
                return Success(True)

            return Success(False)

        finally:
            session.close()

    except OperationalError as e:
        Logger.error(f"Error checking migration status: {str(e)}")
        return Fail(f"Database error: {str(e)}")
    except Exception as e:
        Logger.error(f"Unexpected error checking migration: {str(e)}")
        return Fail(f"Unexpected error: {str(e)}")


def migrate_from_v1_to_v2(
    username: Optional[str] = None,
    password: Optional[str] = None,
    email: Optional[str] = None,
) -> Response[dict]:
    """Migrate database from v1 (plain-text) to v2 (encrypted with users).

    This function:
    1. Creates users table if it doesn't exist
    2. Prompts for user registration if credentials not provided
    3. Retrieves all existing passwords
    4. Encrypts each password with new user's encryption key
    5. Assigns all passwords to the new user
    6. Updates schema to v2 format

    Args:
        username: Username for migration owner (prompts if None)
        password: Master password for migration owner (prompts if None)
        email: Optional email for migration owner

    Returns:
        Response[dict]: Success with migration details, or Fail with error
    """
    Logger.info("\n" + "=" * 60)
    Logger.info("DATABASE MIGRATION REQUIRED")
    Logger.info("=" * 60)
    Logger.info("Your password database needs to be upgraded to the new secure format.")
    Logger.info("All existing passwords will be encrypted with a master password.")
    Logger.info("")

    session = SessionLocal()
    crypto = CryptoService()
    user_repo = UserRepository()

    try:
        # Create tables if they don't exist
        Base.metadata.create_all(engine)

        # Check current schema
        inspector = inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("password_manager")}

        # Determine if we need to add columns
        needs_column_migration = "encrypted_password" not in columns or "nonce" not in columns

        if needs_column_migration:
            Logger.info("Updating database schema...")
            # Add new columns if they don't exist
            _add_v2_columns(session)
            session.commit()

        # Count existing passwords
        result = session.execute(
            text("SELECT COUNT(*) FROM password_manager")
        )
        password_count = result.scalar()

        if password_count == 0:
            Logger.info("No passwords to migrate.")
            return Success({"migrated_count": 0, "user_created": False})

        Logger.info(f"Found {password_count} password(s) to migrate.\n")

        # Get or create migration user
        if username is None:
            Logger.info("Please create an account to become the owner of these passwords.")
            username = input("Username: ").strip()

            if not username:
                return Fail("Username cannot be empty")

        if password is None:
            Logger.info("Enter master password (will be hidden):")
            password = get_password_with_mask()

            if not password:
                return Fail("Password cannot be empty")

            Logger.info("Confirm master password:")
            password_confirm = get_password_with_mask()

            if password != password_confirm:
                return Fail("Passwords do not match")

        # Register the user
        Logger.info(f"\nCreating account for '{username}'...")
        reg_result = user_repo.register(username, password, email)

        if not reg_result.ok:
            return Fail(f"Failed to create user: {reg_result.result}")

        user_id = reg_result.result
        Logger.info(f"Account created successfully! (User ID: {user_id})")

        # Derive encryption key
        user = session.query(User).filter_by(id=user_id).first()
        encryption_key = crypto.derive_encryption_key(
            password, user.salt, user.kdf_iterations
        )

        # Migrate passwords
        Logger.info(f"\nMigrating {password_count} password(s)...")

        # Query passwords directly with SQL since schema might have old column names
        if "user_id" in columns:
            # Schema has user_id, get orphaned passwords
            sql_query = "SELECT * FROM password_manager WHERE user_id IS NULL OR user_id = 0"
        else:
            # Old schema, get all passwords
            sql_query = "SELECT * FROM password_manager"

        result = session.execute(text(sql_query))
        old_passwords = result.fetchall()

        migrated_count = 0
        for row in old_passwords:
            try:
                # Get row data as dict
                row_dict = dict(row._mapping)

                # Get plaintext password
                plaintext_password = None

                # Check for old 'password' column
                if 'password' in row_dict and row_dict['password']:
                    plaintext_password = row_dict['password']
                # Check for 'encrypted_password' that might be plaintext
                elif 'encrypted_password' in row_dict and row_dict['encrypted_password']:
                    ep = row_dict['encrypted_password']
                    # If it's bytes, try to decode
                    if isinstance(ep, bytes):
                        try:
                            plaintext_password = ep.decode('utf-8')
                        except UnicodeDecodeError:
                            # Already encrypted, skip
                            continue
                    else:
                        plaintext_password = ep

                if not plaintext_password:
                    Logger.warning(f"Skipping password ID {row_dict['id']} - no password data")
                    continue

                # Encrypt the password
                ciphertext, nonce = crypto.encrypt_password(
                    plaintext_password, encryption_key
                )

                # Update the row with SQL
                update_sql = """
                    UPDATE password_manager
                    SET user_id = :user_id,
                        encrypted_password = :encrypted_password,
                        nonce = :nonce
                    WHERE id = :id
                """

                session.execute(
                    text(update_sql),
                    {
                        "user_id": user_id,
                        "encrypted_password": ciphertext,
                        "nonce": nonce,
                        "id": row_dict['id']
                    }
                )

                migrated_count += 1

                if migrated_count % 10 == 0:
                    Logger.info(f"  Migrated {migrated_count}/{len(old_passwords)}...")

            except Exception as e:
                Logger.warning(f"Failed to migrate password ID {row_dict.get('id', '?')}: {str(e)}")
                continue

        # Commit all changes
        session.commit()

        Logger.info(f"\n✓ Migration complete!")
        Logger.info(f"  - Migrated passwords: {migrated_count}")
        Logger.info(f"  - Account: {username}")
        Logger.info(f"  - User ID: {user_id}")
        Logger.info(f"\nYou are now logged in. Your passwords are encrypted and secure.")
        Logger.info("=" * 60 + "\n")

        return Success({
            "migrated_count": migrated_count,
            "user_id": user_id,
            "username": username,
            "encryption_key": encryption_key,
            "user_created": True,
        })

    except Exception as e:
        session.rollback()
        Logger.error(f"Migration failed: {str(e)}")
        return Fail(f"Migration error: {str(e)}")

    finally:
        session.close()


def _add_v2_columns(session):
    """Add v2 columns to password_manager table if they don't exist.

    Args:
        session: SQLAlchemy session
    """
    try:
        # Add user_id column if it doesn't exist
        session.execute(
            text(
                "ALTER TABLE password_manager ADD COLUMN user_id INTEGER "
                "REFERENCES users(id) ON DELETE CASCADE"
            )
        )
    except OperationalError:
        # Column already exists
        pass

    try:
        # Add encrypted_password column if it doesn't exist
        session.execute(
            text("ALTER TABLE password_manager ADD COLUMN encrypted_password BLOB")
        )
    except OperationalError:
        pass

    try:
        # Add nonce column if it doesn't exist
        session.execute(
            text("ALTER TABLE password_manager ADD COLUMN nonce BLOB")
        )
    except OperationalError:
        pass

    try:
        # Add tags column if it doesn't exist
        session.execute(
            text("ALTER TABLE password_manager ADD COLUMN tags VARCHAR(255)")
        )
    except OperationalError:
        pass

    try:
        # Add timestamps if they don't exist
        session.execute(
            text("ALTER TABLE password_manager ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        )
    except OperationalError:
        pass

    try:
        session.execute(
            text("ALTER TABLE password_manager ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        )
    except OperationalError:
        pass
