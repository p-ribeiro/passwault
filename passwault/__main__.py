"""Passwault CLI entry point.

This module initializes the database and launches the CLI interface.
Handles automatic migration from old plain-text schema to encrypted schema.
"""

from dotenv import load_dotenv

# Load .env BEFORE importing models (which creates the database engine at import time)
load_dotenv()

from passwault.core.cli import cli  # noqa: E402
from passwault.core.database.models import Base, engine  # noqa: E402
from passwault.core.utils.session_manager import SessionManager  # noqa: E402


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
