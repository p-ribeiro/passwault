"""Passwault CLI entry point.

This module initializes the database and launches the CLI interface.
Handles automatic migration from old plain-text schema to encrypted schema.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def setup_portable_mode():
    """Check for --portable flag and configure portable data directory.

    Must be called before any other imports that use get_data_dir().
    Removes the --portable flag from sys.argv so argparse doesn't see it.
    """
    if "--portable" in sys.argv:
        sys.argv.remove("--portable")

        from passwault.core.utils.data_dir import get_executable_dir, set_portable_data_dir

        exe_dir = get_executable_dir()
        set_portable_data_dir(exe_dir)


# Handle portable mode FIRST, before any config or model imports
setup_portable_mode()


def load_database_config():
    """Load database configuration with fallback chain.

    Priority order:
    1. DATABASE_URL environment variable (highest priority)
    2. ~/.config/passwault/.env config file
    3. Default SQLite (handled by models.py)
    """
    # If DATABASE_URL is already set, use it (highest priority)
    if os.environ.get("DATABASE_URL"):
        return

    # Try loading from user config directory
    config_env_path = Path.home() / ".config" / "passwault" / ".env"
    if config_env_path.exists():
        load_dotenv(config_env_path)
        return

    # Fall back to local .env file (for development)
    load_dotenv()


# Load database config BEFORE importing models (which creates the database engine at import time)
load_database_config()

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
