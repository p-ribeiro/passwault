"""Tests for the portable encrypted vault service."""

import gzip
import json
import sqlite3
import stat
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from passwault.core.services.vault_service import MAGIC, KdfParams, VaultService
from passwault.core.utils.local_types import VaultError
from passwault.core.utils.session_manager import SessionManager

# Cheap Argon2id parameters so tests stay fast
FAST = KdfParams(memory_kib=64, iterations=1, lanes=1)


@pytest.fixture
def home(tmp_path):
    path = tmp_path / "stick" / "passwault"
    path.mkdir(parents=True)
    return path


def _vault(home, state_dir) -> VaultService:
    state_dir.mkdir(mode=0o700, exist_ok=True)
    return VaultService(home=home, state_dir=state_dir, kdf_params=FAST)


@pytest.fixture
def vault(home, tmp_path):
    return _vault(home, tmp_path / "state")


@pytest.fixture
def session_manager():
    return MagicMock(spec=SessionManager)


def _add_rows(db_path, *names):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS entries (name TEXT)")
    conn.executemany("INSERT INTO entries VALUES (?)", [(n,) for n in names])
    conn.commit()
    conn.close()


def _rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT name FROM entries ORDER BY name")]
    finally:
        conn.close()


def _make_sqlite_file(path, *names):
    _add_rows(path, *names)
    return path


class TestInitAndOpen:
    def test_requires_portable_mode(self):
        with pytest.raises(VaultError, match="portable mode"):
            VaultService()

    def test_init_creates_encrypted_vault_and_opens(self, vault):
        vault.init("vault-pw")

        assert vault.exists()
        assert vault.is_open()
        assert vault.vault_path.read_bytes().startswith(MAGIC)
        assert stat.S_IMODE(vault.db_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(vault.meta_path.stat().st_mode) == 0o600

    def test_init_refuses_existing_vault(self, vault):
        vault.init("vault-pw")
        vault.close()

        with pytest.raises(VaultError, match="already exists"):
            vault.init("other")

    def test_roundtrip_keeps_data_and_hides_plaintext(self, vault):
        vault.init("vault-pw")
        _add_rows(vault.db_path, "github-secret-site")
        vault.close()

        assert not vault.is_open()
        assert not vault.db_path.exists()
        assert b"github-secret-site" not in vault.vault_path.read_bytes()

        vault.open("vault-pw")
        assert _rows(vault.db_path) == ["github-secret-site"]

    def test_open_wrong_password(self, vault):
        vault.init("vault-pw")
        vault.close()

        with pytest.raises(VaultError, match="Wrong vault password"):
            vault.open("nope")
        assert not vault.is_open()

    def test_open_when_already_open(self, vault):
        vault.init("vault-pw")
        with pytest.raises(VaultError, match="already open"):
            vault.open("vault-pw")

    def test_open_missing_vault(self, vault):
        with pytest.raises(VaultError, match="No vault found"):
            vault.open("vault-pw")


class TestTampering:
    def _closed_vault(self, vault):
        vault.init("vault-pw")
        _add_rows(vault.db_path, "x")
        vault.close()
        return bytearray(vault.vault_path.read_bytes())

    def test_tampered_ciphertext(self, vault):
        blob = self._closed_vault(vault)
        blob[-1] ^= 0x01
        vault.vault_path.write_bytes(bytes(blob))

        with pytest.raises(VaultError, match="Wrong vault password or corrupted"):
            vault.open("vault-pw")

    def test_tampered_header_params(self, vault):
        blob = self._closed_vault(vault)
        # iterations field follows memory_kib in the header
        blob[len(MAGIC) + 4 : len(MAGIC) + 8] = (2).to_bytes(4, "big")
        vault.vault_path.write_bytes(bytes(blob))

        with pytest.raises(VaultError, match="Wrong vault password or corrupted"):
            vault.open("vault-pw")

    def test_rejects_absurd_kdf_params(self, vault):
        blob = self._closed_vault(vault)
        blob[len(MAGIC) : len(MAGIC) + 4] = (0xFFFFFFFF).to_bytes(4, "big")
        vault.vault_path.write_bytes(bytes(blob))

        with pytest.raises(VaultError, match="invalid key-derivation"):
            vault.open("vault-pw")

    def test_not_a_vault_file(self, vault):
        vault.vault_path.parent.mkdir(parents=True)
        vault.vault_path.write_bytes(b"definitely not a vault" * 4)

        with pytest.raises(VaultError, match="Not a passwault vault"):
            vault.open("vault-pw")


class TestSealAndClose:
    def test_seal_only_when_dirty(self, vault):
        vault.init("vault-pw")
        assert vault.seal_if_dirty() is False

        _add_rows(vault.db_path, "a")
        assert vault.seal_if_dirty() is True
        assert vault.backup_path.exists()
        assert vault.seal_if_dirty() is False

    def test_close_wipes_host_state(self, vault):
        vault.init("vault-pw")
        vault.close()

        assert not vault.db_path.exists()
        assert not vault.meta_path.exists()

    def test_close_discard_drops_changes(self, vault):
        vault.init("vault-pw")
        _add_rows(vault.db_path, "keep")
        vault.seal_if_dirty()
        _add_rows(vault.db_path, "drop")

        vault.close(discard=True)
        vault.open("vault-pw")

        assert _rows(vault.db_path) == ["keep"]

    def test_seal_with_drive_missing_keeps_host_copy(self, vault):
        vault.init("vault-pw")
        _add_rows(vault.db_path, "pending")
        for path in vault.vault_path.parent.iterdir():
            path.unlink()
        vault.vault_path.parent.rmdir()

        with pytest.raises(VaultError, match="Drive not available"):
            vault.seal_if_dirty()
        assert vault.is_open()
        assert _rows(vault.db_path) == ["pending"]

    def test_touch_updates_last_used(self, vault):
        vault.init("vault-pw")
        meta = json.loads(vault.meta_path.read_text())
        meta["last_used"] = "2000-01-01T00:00:00"
        vault.meta_path.write_text(json.dumps(meta))

        vault.touch()

        assert json.loads(vault.meta_path.read_text())["last_used"] > "2000"
        assert vault.status()["last_used"].startswith(str(datetime.now().year))


class TestChangePassword:
    def test_change_password(self, vault):
        vault.init("old-pw")
        _add_rows(vault.db_path, "entry")
        vault.change_password("old-pw", "new-pw")
        vault.close()

        with pytest.raises(VaultError):
            vault.open("old-pw")
        vault.open("new-pw")
        assert _rows(vault.db_path) == ["entry"]

    def test_change_password_wrong_current(self, vault):
        vault.init("old-pw")
        with pytest.raises(VaultError, match="incorrect"):
            vault.change_password("wrong", "new-pw")

    def test_change_password_requires_open_vault(self, vault):
        with pytest.raises(VaultError, match="not open"):
            vault.change_password("a", "b")


class TestImport:
    def test_import_sqlite_db(self, vault, tmp_path):
        source = _make_sqlite_file(tmp_path / "host.db", "bank", "mail")

        vault.init("vault-pw", import_db=source)

        assert _rows(vault.db_path) == ["bank", "mail"]

    def test_import_gzipped_backup(self, vault, tmp_path):
        source = _make_sqlite_file(tmp_path / "host.db", "bank")
        gz = tmp_path / "passwault_20260101_000000.db.gz"
        gz.write_bytes(gzip.compress(source.read_bytes()))

        vault.init("vault-pw", import_db=gz)

        assert _rows(vault.db_path) == ["bank"]

    def test_import_rejects_non_sqlite(self, vault, tmp_path):
        bogus = tmp_path / "bogus.db"
        bogus.write_bytes(b"hello")

        with pytest.raises(VaultError, match="Not a SQLite database"):
            vault.init("vault-pw", import_db=bogus)
        assert not vault.exists()

    def test_import_missing_file(self, vault, tmp_path):
        with pytest.raises(VaultError, match="File not found"):
            vault.init("vault-pw", import_db=tmp_path / "missing.db")


class TestReconcile:
    def test_idle_vault_is_closed(self, vault, session_manager):
        vault.init("vault-pw")
        _add_rows(vault.db_path, "unsaved")
        meta = json.loads(vault.meta_path.read_text())
        idle_since = datetime.now() - timedelta(
            minutes=VaultService.IDLE_TIMEOUT_MINUTES + 1
        )
        meta["last_used"] = idle_since.isoformat()
        vault.meta_path.write_text(json.dumps(meta))

        vault.reconcile(session_manager)

        assert not vault.is_open()
        session_manager.logout.assert_called_once()
        vault.open("vault-pw")
        assert _rows(vault.db_path) == ["unsaved"]

    def test_active_vault_stays_open(self, vault, session_manager):
        vault.init("vault-pw")

        vault.reconcile(session_manager)

        assert vault.is_open()
        session_manager.logout.assert_not_called()

    def test_stale_vault_with_local_changes_writes_conflict(
        self, home, tmp_path, session_manager
    ):
        here = _vault(home, tmp_path / "host-a")
        here.init("vault-pw")

        # Same stick used on another machine without closing here first
        elsewhere = _vault(home, tmp_path / "host-b")
        elsewhere.open("vault-pw")
        _add_rows(elsewhere.db_path, "from-b")
        elsewhere.close()

        _add_rows(here.db_path, "from-a")
        with pytest.raises(VaultError, match="changed since it was opened"):
            here.seal_if_dirty()

        here.reconcile(session_manager)

        assert not here.is_open()
        session_manager.logout.assert_called_once()
        conflicts = list(home.joinpath("data").glob("vault.pwv.conflict-*"))
        assert len(conflicts) == 1
        assert VaultService.is_vault_file(conflicts[0])

        here.open("vault-pw")
        assert _rows(here.db_path) == ["from-b"]

    def test_stale_clean_vault_just_closes(self, home, tmp_path, session_manager):
        here = _vault(home, tmp_path / "host-a")
        here.init("vault-pw")
        elsewhere = _vault(home, tmp_path / "host-b")
        elsewhere.open("vault-pw")
        _add_rows(elsewhere.db_path, "from-b")
        elsewhere.close()

        here.reconcile(session_manager)

        assert not here.is_open()
        assert not list(home.joinpath("data").glob("vault.pwv.conflict-*"))

    def test_partial_state_is_wiped(self, vault, session_manager):
        vault.db_path.write_bytes(b"leftover")

        vault.reconcile(session_manager)

        assert not vault.db_path.exists()
