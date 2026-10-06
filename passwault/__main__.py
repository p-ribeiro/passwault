"""Passwault CLI entry point.

This module initializes the database and launches the CLI interface.
In portable mode it also reconciles, and afterwards seals, the USB vault.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

from passwault.core.config import Config


def load_database_config():
    """Load database configuration with fallback chain.

    Priority order:
    1. DATABASE_URL environment variable (highest priority)
    2. ~/.config/passwault/.env config file
    3. Default SQLite (handled by models.py)

    Portable mode reads no host configuration at all.
    """
    if Config.is_portable():
        return

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
from passwault.core.services.vault_service import VaultService  # noqa: E402
from passwault.core.utils.local_types import VaultError  # noqa: E402
from passwault.core.utils.logger import Logger  # noqa: E402
from passwault.core.utils.session_manager import SessionManager  # noqa: E402


def _seal_vault(vault: VaultService) -> None:
    """Write host-side changes back to the drive after a command."""
    engine.dispose()
    try:
        vault.seal_if_dirty()
    except VaultError as e:
        Logger.error(f"Could not save the vault to the drive: {e}")
    vault.touch()


def main():
    """Main entry point for Passwault CLI.

    Initializes database tables and starts the CLI with session management.
    """
    session_manager = SessionManager()

    vault = VaultService() if Config.is_portable() else None
    if vault is not None:
        vault.reconcile(session_manager)

    # Create database tables if they don't exist (portable: only once unlocked)
    if vault is None or vault.is_open():
        Base.metadata.create_all(engine)

    # Check and expire stale sessions
    session_manager.expire_session()

    try:
        cli(session_manager=session_manager)
    finally:
        if vault is not None and vault.is_open():
            _seal_vault(vault)


if __name__ == "__main__":
    main()
