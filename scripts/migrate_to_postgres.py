#!/usr/bin/env python3
"""Migration script from SQLite to PostgreSQL.

This script migrates all users and their encrypted passwords from a SQLite
database to a PostgreSQL database. The encrypted data is copied as-is,
preserving the encryption.

Usage:
    python scripts/migrate_to_postgres.py \\
        --sqlite-path ~/.local/share/passwault/passwault.db \\
        --postgres-url postgresql://user:pass@localhost:5432/passwault

Options:
    --dry-run    Show what would be migrated without making changes
    --verbose    Show detailed progress information
"""

import argparse
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from passwault.core.database.models import Base, User, PasswordManager  # noqa: E402


def check_sqlite_exists(sqlite_path: str) -> bool:
    """Check if SQLite database file exists."""
    path = Path(sqlite_path)
    if not path.exists():
        print(f"Error: SQLite database not found: {sqlite_path}")
        return False
    return True


def check_postgres_connection(postgres_url: str) -> bool:
    """Check if PostgreSQL connection works."""
    try:
        engine = create_engine(postgres_url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception as e:
        print(f"Error: Cannot connect to PostgreSQL: {e}")
        return False


def get_table_counts(session) -> dict:
    """Get counts of records in each table."""
    user_count = session.query(User).count()
    password_count = session.query(PasswordManager).count()
    return {"users": user_count, "passwords": password_count}


def migrate(
    sqlite_path: str,
    postgres_url: str,
    dry_run: bool = False,
    verbose: bool = False,
):
    """Migrate data from SQLite to PostgreSQL.

    Args:
        sqlite_path: Path to SQLite database file
        postgres_url: PostgreSQL connection URL
        dry_run: If True, show what would be migrated without executing
        verbose: If True, show detailed progress
    """
    # Connect to SQLite
    sqlite_engine = create_engine(f"sqlite:///{sqlite_path}")
    SqliteSession = sessionmaker(bind=sqlite_engine)
    sqlite_session = SqliteSession()

    # Connect to PostgreSQL
    postgres_engine = create_engine(postgres_url)

    if not dry_run:
        # Create tables in PostgreSQL
        print("Creating tables in PostgreSQL...")
        Base.metadata.create_all(postgres_engine)

    PostgresSession = sessionmaker(bind=postgres_engine)
    postgres_session = PostgresSession()

    try:
        # Get source counts
        source_counts = get_table_counts(sqlite_session)
        print("\nSource database (SQLite):")
        print(f"  Users: {source_counts['users']}")
        print(f"  Passwords: {source_counts['passwords']}")

        if source_counts["users"] == 0:
            print("\nNo data to migrate.")
            return

        # Check if destination already has data
        if not dry_run:
            dest_counts = get_table_counts(postgres_session)
            if dest_counts["users"] > 0:
                print("\nWarning: PostgreSQL database already has data:")
                print(f"  Users: {dest_counts['users']}")
                print(f"  Passwords: {dest_counts['passwords']}")
                response = input("Continue and add to existing data? [y/N]: ")
                if response.lower() != "y":
                    print("Migration cancelled.")
                    return

        # Migrate users
        users = sqlite_session.query(User).all()
        print(f"\nMigrating {len(users)} user(s)...")

        user_id_map = {}  # Map old user IDs to new user IDs

        for user in users:
            if verbose:
                print(f"  Processing user: {user.username}")

            if dry_run:
                print(f"  [DRY RUN] Would migrate user: {user.username}")
                user_id_map[user.id] = user.id  # Keep same ID for dry run
                continue

            # Create new user in PostgreSQL
            new_user = User(
                username=user.username,
                email=user.email,
                master_password_hash=user.master_password_hash,
                salt=user.salt,
                kdf_algorithm=user.kdf_algorithm,
                kdf_iterations=user.kdf_iterations,
                created_at=user.created_at,
                updated_at=user.updated_at,
                last_login=user.last_login,
            )
            postgres_session.add(new_user)
            postgres_session.flush()  # Get the new ID

            user_id_map[user.id] = new_user.id

            if verbose:
                print(f"    Migrated user ID {user.id} -> {new_user.id}")

        # Migrate passwords
        passwords = sqlite_session.query(PasswordManager).all()
        print(f"\nMigrating {len(passwords)} password(s)...")

        migrated_passwords = 0
        for pwd in passwords:
            if verbose:
                print(f"  Processing password: {pwd.resource_name} (user_id={pwd.user_id})")

            if pwd.user_id not in user_id_map:
                print(f"  Warning: Skipping orphaned password {pwd.resource_name} (user_id={pwd.user_id})")
                continue

            if dry_run:
                print(f"  [DRY RUN] Would migrate password: {pwd.resource_name}")
                migrated_passwords += 1
                continue

            new_pwd = PasswordManager(
                user_id=user_id_map[pwd.user_id],
                resource_name=pwd.resource_name,
                username=pwd.username,
                encrypted_password=pwd.encrypted_password,
                nonce=pwd.nonce,
                website=pwd.website,
                description=pwd.description,
                tags=pwd.tags,
                created_at=pwd.created_at,
                updated_at=pwd.updated_at,
            )
            postgres_session.add(new_pwd)
            migrated_passwords += 1

            if verbose:
                print(f"    Migrated password for user_id {pwd.user_id} -> {user_id_map[pwd.user_id]}")

        if not dry_run:
            postgres_session.commit()
            print("\nMigration completed successfully!")
            print(f"  Users migrated: {len(users)}")
            print(f"  Passwords migrated: {migrated_passwords}")

            # Verify migration
            dest_counts = get_table_counts(postgres_session)
            print("\nDestination database (PostgreSQL):")
            print(f"  Users: {dest_counts['users']}")
            print(f"  Passwords: {dest_counts['passwords']}")
        else:
            print("\n[DRY RUN] Migration preview completed.")
            print(f"  Users would be migrated: {len(users)}")
            print(f"  Passwords would be migrated: {migrated_passwords}")

    except Exception as e:
        postgres_session.rollback()
        print(f"\nMigration failed: {e}")
        raise

    finally:
        sqlite_session.close()
        postgres_session.close()
        sqlite_engine.dispose()
        postgres_engine.dispose()


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Passwault database from SQLite to PostgreSQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview migration (no changes made)
  python scripts/migrate_to_postgres.py \\
      --sqlite-path ~/.local/share/passwault/passwault.db \\
      --postgres-url postgresql://passwault:pass@localhost:5432/passwault \\
      --dry-run

  # Run migration with verbose output
  python scripts/migrate_to_postgres.py \\
      --sqlite-path ~/.local/share/passwault/passwault.db \\
      --postgres-url postgresql://passwault:pass@localhost:5432/passwault \\
      --verbose
        """,
    )
    parser.add_argument(
        "--sqlite-path",
        required=True,
        help="Path to SQLite database file",
    )
    parser.add_argument(
        "--postgres-url",
        required=True,
        help="PostgreSQL connection URL (e.g., postgresql://user:pass@host:5432/db)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without making changes",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed progress information",
    )

    args = parser.parse_args()

    # Validate inputs
    if not check_sqlite_exists(args.sqlite_path):
        sys.exit(1)

    if not args.dry_run and not check_postgres_connection(args.postgres_url):
        sys.exit(1)

    # Run migration
    migrate(
        sqlite_path=args.sqlite_path,
        postgres_url=args.postgres_url,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
