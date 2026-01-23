"""Passwault CLI entry point.

This module initializes the database and launches the CLI interface.
Handles automatic migration from old plain-text schema to encrypted schema.
"""

from passwault.core.cli import cli
from passwault.core.database.models import Base, engine
from passwault.core.utils.session_manager import SessionManager


def main():
    """Main entry point for Passwault CLI.

    Initializes database tables and starts the CLI with session management.
    """
    # Create database tables if they don't exist
    Base.metadata.create_all(engine)

    # Initialize session manager
    session_manager = SessionManager()

    # Check and expire stale sessions
    session_manager.expire_session()

    # Start CLI
    cli(session_manager=session_manager)


if __name__ == "__main__":
    main()
