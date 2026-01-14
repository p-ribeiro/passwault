"""Passwault CLI entry point.

This module initializes the database and launches the CLI interface.
Handles automatic migration from old plain-text schema to encrypted schema.
"""

from passwault.core.cli import cli
from passwault.core.database.migrations import check_migration_needed, migrate_from_v1_to_v2
from passwault.core.database.models import Base, engine
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


def main():
    """Main entry point for Passwault CLI.

    Initializes database tables and starts the CLI with session management.
    Automatically detects and handles migration from v1 to v2 schema.
    """
    # Create database tables if they don't exist
    Base.metadata.create_all(engine)

    # Check if migration is needed
    migration_check = check_migration_needed()

    if not migration_check.ok:
        Logger.error(f"Failed to check migration status: {migration_check.result}")
        return

    # Initialize session manager
    session_manager = SessionManager()

    # If migration is needed, perform it
    if migration_check.result:
        Logger.info("\n[INFO] Database migration required.")
        Logger.info("[INFO] Your existing passwords will be encrypted and secured.\n")

        # Perform migration
        migration_result = migrate_from_v1_to_v2()

        if not migration_result.ok:
            Logger.error(f"Migration failed: {migration_result.result}")
            Logger.error("Please contact support or check the error logs.")
            return

        # If migration created a user, create session automatically
        if migration_result.result.get("user_created"):
            user_data = {
                "user_id": migration_result.result["user_id"],
                "username": migration_result.result["username"],
                "encryption_key": migration_result.result["encryption_key"],
            }
            session_manager.create_session(user_data)
            Logger.info("You are now logged in and can use password commands.\n")

    # Check and expire stale sessions
    session_manager.expire_session()

    # Start CLI
    cli(session_manager=session_manager)


if __name__ == "__main__":
    main()
