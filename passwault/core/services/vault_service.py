"""Encrypted vault file for portable mode.

On the stick the SQLite database is a single AES-256-GCM file (data/vault.pwv).
While the vault is open it is decrypted into the private host state dir, and
every change is sealed back onto the stick.
"""

import base64
import gzip
import hashlib
import hmac
import json
import os
import shutil
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from passwault.core.config import Config
from passwault.core.services.crypto_service import CryptoService
from passwault.core.utils.file_handler import write_private_file
from passwault.core.utils.local_types import VaultError
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager

MAGIC = b"PWVAULT\x01"
_PARAMS = struct.Struct(">III")
SALT_LENGTH = 16
NONCE_LENGTH = CryptoService.DEFAULT_NONCE_LENGTH
HEADER_LENGTH = len(MAGIC) + _PARAMS.size + SALT_LENGTH
SQLITE_HEADER = b"SQLite format 3\x00"

# Upper bounds that stop a tampered header from forcing a huge KDF run
MAX_MEMORY_KIB = 1 << 20
MAX_ITERATIONS = 100
MAX_LANES = 64


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters stored in the vault header."""

    memory_kib: int = 64 * 1024
    iterations: int = 3
    lanes: int = 4


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str | None:
    try:
        return _sha256(path.read_bytes())
    except FileNotFoundError:
        return None


def _shred(path: Path) -> None:
    """Zero a file's contents before unlinking it (effective on tmpfs)."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    with open(path, "r+b") as f:
        f.write(b"\0" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink()


def _fsync_dir(path: Path) -> None:
    """Best-effort directory fsync; some filesystems (drvfs, vfat) refuse it."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class VaultService:
    """Open, seal and close the portable encrypted vault."""

    IDLE_TIMEOUT_MINUTES = 30

    def __init__(
        self,
        home: Path | None = None,
        state_dir: Path | None = None,
        kdf_params: KdfParams | None = None,
    ):
        home = home or Config.get_portable_home()
        if home is None:
            raise VaultError(
                "Vault commands are only available in portable mode "
                "(run from the USB bundle or set PASSWAULT_HOME)"
            )

        self.home = home
        self.vault_path = home / "data" / "vault.pwv"
        self.backup_path = self.vault_path.with_name("vault.pwv.bak")
        self.state_dir = state_dir or Config.get_state_dir()
        self.db_path = self.state_dir / "passwault.db"
        self.meta_path = self.state_dir / "vault.json"
        self.kdf_params = kdf_params or KdfParams()

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self.vault_path.is_file()

    def is_open(self) -> bool:
        return self.db_path.is_file() and self.meta_path.is_file()

    def is_dirty(self) -> bool:
        meta = self._load_meta()
        return _sha256_file(self.db_path) != meta["db_sha256"]

    def status(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "home": self.home,
            "vault_path": self.vault_path,
            "exists": self.exists(),
            "open": self.is_open(),
        }
        if info["open"]:
            meta = self._load_meta()
            info["last_used"] = meta["last_used"]
            info["dirty"] = self.is_dirty()
        return info

    @staticmethod
    def is_vault_file(path: Path) -> bool:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def init(self, password: str, import_db: Path | None = None) -> None:
        """Create a new vault (empty or from an existing SQLite DB) and open it."""
        if self.exists():
            raise VaultError(f"A vault already exists at {self.vault_path}")

        data = self._read_import(import_db) if import_db else b""

        self._wipe_state()
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

        salt = os.urandom(SALT_LENGTH)
        key = self._derive(password, salt, self.kdf_params)
        write_private_file(self.db_path, data)
        meta = self._new_meta(key, salt, self.kdf_params, db_sha256=None)
        meta["vault_sha256"] = None
        self._seal(meta)

    def open(self, password: str) -> None:
        """Decrypt the vault from the stick into the host state dir."""
        if self.is_open():
            raise VaultError("Vault is already open")
        if not self.exists():
            raise VaultError(
                f"No vault found at {self.vault_path}. Run: passwault vault init"
            )

        blob = self.vault_path.read_bytes()
        params, salt, nonce, ciphertext, aad = self._parse(blob)
        key = self._derive(password, salt, params)

        try:
            plaintext = CryptoService.decrypt_bytes(ciphertext, nonce, key, aad)
        except InvalidTag:
            raise VaultError("Wrong vault password or corrupted vault file")

        self._wipe_state()
        write_private_file(self.db_path, plaintext)
        meta = self._new_meta(key, salt, params, db_sha256=_sha256(plaintext))
        meta["vault_sha256"] = _sha256(blob)
        self._save_meta(meta)

    def seal_if_dirty(self) -> bool:
        """Write the host copy back to the stick if it changed. Returns True if sealed."""
        if not self.is_dirty():
            return False
        self._seal(self._load_meta())
        return True

    def close(self, discard: bool = False) -> None:
        """Seal pending changes (unless discarding) and wipe the host copy."""
        if not self.is_open():
            return
        if not discard:
            self.seal_if_dirty()
        self._wipe_state()

    def change_password(self, old_password: str, new_password: str) -> None:
        """Re-encrypt the vault under a new password (vault must be open)."""
        if not self.is_open():
            raise VaultError("Vault is not open. Run: passwault vault open")

        meta = self._load_meta()
        params = KdfParams(meta["memory_kib"], meta["iterations"], meta["lanes"])
        old_key = self._derive(old_password, self._b64(meta["salt"]), params)
        if not hmac.compare_digest(old_key, self._b64(meta["key"])):
            raise VaultError("Current vault password is incorrect")

        salt = os.urandom(SALT_LENGTH)
        key = self._derive(new_password, salt, self.kdf_params)
        new_meta = self._new_meta(key, salt, self.kdf_params, meta["db_sha256"])
        new_meta["vault_sha256"] = meta["vault_sha256"]
        self._seal(new_meta)

    def touch(self) -> None:
        """Record activity for the idle timeout."""
        if self.is_open():
            meta = self._load_meta()
            meta["last_used"] = datetime.now().isoformat()
            self._save_meta(meta)

    def reconcile(self, session_manager: SessionManager) -> None:
        """Close a stale or idle vault at startup.

        A vault is stale when the file on the stick changed since it was opened
        here (e.g. the stick was used on another machine without closing).
        """
        if not self.is_open():
            # Leftovers from an interrupted open/close
            if self.db_path.exists() or self.meta_path.exists():
                self._wipe_state()
            return

        if not self.home.is_dir():
            return  # drive not mounted; keep host state until it comes back

        meta = self._load_meta()

        if _sha256_file(self.vault_path) != meta["vault_sha256"]:
            if self.is_dirty():
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                conflict = self.vault_path.with_name(f"vault.pwv.conflict-{stamp}")
                self._write_vault_file(conflict, meta, self.db_path.read_bytes())
                Logger.warn(
                    "The vault on the drive changed on another machine. Unsaved "
                    f"changes from this host were saved to {conflict}"
                )
            else:
                Logger.warn("The vault on the drive changed on another machine")
            self._wipe_state()
            session_manager.logout()
            Logger.info("Closed the stale vault copy. Run: passwault vault open")
            return

        idle = datetime.now() - datetime.fromisoformat(meta["last_used"])
        if idle >= timedelta(minutes=self.IDLE_TIMEOUT_MINUTES):
            try:
                self.close()
            except VaultError as e:
                Logger.error(f"Could not auto-close idle vault: {e}")
                return
            session_manager.logout()
            Logger.info("Vault closed due to inactivity. Run: passwault vault open")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _seal(self, meta: dict[str, Any]) -> None:
        if not self.vault_path.parent.is_dir():
            raise VaultError(
                f"Drive not available ({self.vault_path.parent}); "
                "changes are kept on this host until the next run"
            )
        if _sha256_file(self.vault_path) != meta["vault_sha256"]:
            raise VaultError(
                "The vault on the drive changed since it was opened; "
                "refusing to overwrite it"
            )

        plaintext = self.db_path.read_bytes()
        tmp = self.vault_path.with_name(self.vault_path.name + ".tmp")
        blob = self._write_vault_file(tmp, meta, plaintext)

        if self.vault_path.exists():
            shutil.copyfile(self.vault_path, self.backup_path)
        os.replace(tmp, self.vault_path)
        _fsync_dir(self.vault_path.parent)

        meta["db_sha256"] = _sha256(plaintext)
        meta["vault_sha256"] = _sha256(blob)
        self._save_meta(meta)

    def _write_vault_file(
        self, path: Path, meta: dict[str, Any], plaintext: bytes
    ) -> bytes:
        aad = (
            MAGIC
            + _PARAMS.pack(meta["memory_kib"], meta["iterations"], meta["lanes"])
            + self._b64(meta["salt"])
        )
        ciphertext, nonce = CryptoService.encrypt_bytes(
            plaintext, self._b64(meta["key"]), aad
        )
        blob = aad + nonce + ciphertext

        with open(path, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        return blob

    @staticmethod
    def _parse(blob: bytes) -> tuple[KdfParams, bytes, bytes, bytes, bytes]:
        if len(blob) < HEADER_LENGTH + NONCE_LENGTH + 16 or not blob.startswith(MAGIC):
            raise VaultError("Not a passwault vault file (or unsupported version)")

        memory_kib, iterations, lanes = _PARAMS.unpack_from(blob, len(MAGIC))
        if not (
            1 <= lanes <= MAX_LANES
            and 8 * lanes <= memory_kib <= MAX_MEMORY_KIB
            and 1 <= iterations <= MAX_ITERATIONS
        ):
            raise VaultError("Vault file has invalid key-derivation parameters")

        salt = blob[HEADER_LENGTH - SALT_LENGTH : HEADER_LENGTH]
        nonce = blob[HEADER_LENGTH : HEADER_LENGTH + NONCE_LENGTH]
        ciphertext = blob[HEADER_LENGTH + NONCE_LENGTH :]
        aad = blob[:HEADER_LENGTH]
        return KdfParams(memory_kib, iterations, lanes), salt, nonce, ciphertext, aad

    @staticmethod
    def _derive(password: str, salt: bytes, params: KdfParams) -> bytes:
        return CryptoService.derive_key_argon2id(
            password, salt, params.memory_kib, params.iterations, params.lanes
        )

    @staticmethod
    def _read_import(path: Path) -> bytes:
        if not path.is_file():
            raise VaultError(f"File not found: {path}")
        try:
            data = path.read_bytes()
            if path.suffix == ".gz":
                data = gzip.decompress(data)
        except (OSError, EOFError) as e:
            raise VaultError(f"Could not read {path}: {e}")
        if not data.startswith(SQLITE_HEADER):
            raise VaultError(f"Not a SQLite database: {path}")
        return data

    @staticmethod
    def _b64(value: str) -> bytes:
        return base64.b64decode(value)

    def _new_meta(
        self, key: bytes, salt: bytes, params: KdfParams, db_sha256: str | None
    ) -> dict[str, Any]:
        return {
            "key": base64.b64encode(key).decode(),
            "salt": base64.b64encode(salt).decode(),
            "memory_kib": params.memory_kib,
            "iterations": params.iterations,
            "lanes": params.lanes,
            "db_sha256": db_sha256,
            "last_used": datetime.now().isoformat(),
        }

    def _load_meta(self) -> dict[str, Any]:
        try:
            return json.loads(self.meta_path.read_text())
        except (OSError, ValueError) as e:
            raise VaultError(f"Vault state is unreadable: {e}")

    def _save_meta(self, meta: dict[str, Any]) -> None:
        write_private_file(self.meta_path, json.dumps(meta).encode())

    def _wipe_state(self) -> None:
        for path in (
            self.db_path,
            self.db_path.with_name(self.db_path.name + "-journal"),
            self.meta_path,
        ):
            _shred(path)
