"""Portable vault commands: init, open, close, status and change-password.

The vault password unlocks the encrypted database file on the USB stick;
user master passwords still protect each user's entries inside it.
"""

from datetime import datetime
from pathlib import Path

from passwault.core.database import models
from passwault.core.services.vault_service import VaultService
from passwault.core.utils.local_types import VaultError
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask
from passwault.core.utils.session_manager import SessionManager


def _prompt_new_password() -> str | None:
    """Prompt for a new vault password twice; None if empty or mismatched."""
    Logger.info("Enter new vault password (will be hidden):")
    password = get_password_with_mask()
    if not password:
        Logger.error("Password cannot be empty")
        return None

    Logger.info("Confirm vault password:")
    if password != get_password_with_mask():
        Logger.error("Passwords do not match")
        return None

    return password


def init_vault(password: str | None, import_db: str | None) -> None:
    """Create the encrypted vault on the stick, optionally importing a SQLite DB."""
    try:
        vault = VaultService()
        if vault.exists():
            raise VaultError(f"A vault already exists at {vault.vault_path}")

        if password is None:
            password = _prompt_new_password()
            if password is None:
                return

        vault.init(password, Path(import_db) if import_db else None)
        models.Base.metadata.create_all(models.engine)
        vault.seal_if_dirty()
    except VaultError as e:
        Logger.error(str(e))
        return

    Logger.info(f"Vault created and opened: {vault.vault_path}")
    if import_db:
        Logger.info(
            f"Imported {import_db}. If it is a plaintext copy you no longer need, "
            "delete it: it exposes your entry names and usernames."
        )
    else:
        Logger.info("Next: passwault auth register -u <username>")


def open_vault(password: str | None) -> None:
    """Decrypt the vault into private host memory for this session."""
    try:
        vault = VaultService()
        if vault.is_open():
            Logger.info("Vault is already open")
            return
        if not vault.exists():
            raise VaultError(
                f"No vault found at {vault.vault_path}. Run: passwault vault init"
            )

        if password is None:
            Logger.info("Enter vault password (will be hidden):")
            password = get_password_with_mask()

        vault.open(password)
        models.Base.metadata.create_all(models.engine)
    except VaultError as e:
        Logger.error(str(e))
        return

    Logger.info("Vault opened. Run `passwault vault close` before removing the drive.")


def close_vault(session_manager: SessionManager, discard: bool = False) -> None:
    """Save pending changes to the stick, wipe the host copy and log out."""
    try:
        vault = VaultService()
        if vault.is_open():
            models.engine.dispose()
            vault.close(discard=discard)
        else:
            Logger.info("Vault is not open")
        session_manager.logout()
    except VaultError as e:
        Logger.error(f"{e}. Use --discard to drop the host copy anyway.")
        return

    if discard:
        Logger.warn("Vault closed without saving host changes")
    Logger.info(
        "Vault closed. Safe to remove the drive (eject it or run `sync` first)."
    )


def vault_status() -> None:
    """Print where the vault lives and whether it is open."""
    try:
        info = VaultService().status()
    except VaultError as e:
        Logger.error(str(e))
        return

    print(f"  Portable home: {info['home']}")
    print(f"  Vault file:    {info['vault_path']}")
    if not info["exists"]:
        print("  State:         not created (run: passwault vault init)")
    elif info["open"]:
        last_used = datetime.fromisoformat(info["last_used"])
        unsaved = ", unsaved changes" if info["dirty"] else ""
        print(
            f"  State:         open (last activity {last_used:%Y-%m-%d %H:%M:%S}{unsaved})"
        )
    else:
        print("  State:         locked")


def change_vault_password(old_password: str | None, new_password: str | None) -> None:
    """Re-encrypt the vault with a new vault password."""
    try:
        vault = VaultService()
        if not vault.is_open():
            raise VaultError("Vault is not open. Run: passwault vault open")

        if old_password is None:
            Logger.info("Enter current vault password (will be hidden):")
            old_password = get_password_with_mask()

        if new_password is None:
            new_password = _prompt_new_password()
            if new_password is None:
                return

        vault.change_password(old_password, new_password)
    except VaultError as e:
        Logger.error(str(e))
        return

    Logger.info("Vault password changed")
