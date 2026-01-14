import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from PIL import Image

from passwault.core.utils.session_manager import SessionManager


@pytest.fixture
def tmp_image_rgb(tmp_path):
    test_image_path = tmp_path / "test_rgb.png"
    Image.new("RGB", (300, 200), color=(102, 200, 235)).save(test_image_path)
    return test_image_path

@pytest.fixture
def tmp_image_rgba(tmp_path):
    test_image_path = tmp_path / "test_rgba.png"
    Image.new("RGBA", (300, 200), color=(102, 200, 235)).save(test_image_path)
    return test_image_path

@pytest.fixture
def tmp_image_rgb_jpeg(tmp_path):
    test_image_path = tmp_path / "test_rgb.jpg"
    Image.new("RGB", (300, 200), color=(102, 200, 235)).save(test_image_path, format="JPEG")
    return test_image_path

@pytest.fixture
def tmp_image_bw(tmp_path):
    test_image_path = tmp_path / "test_bw.png"
    Image.new("L", (300, 200)).save(test_image_path)
    return test_image_path

@pytest.fixture
def new_band_values():
    return [111] * (200 * 300)

@pytest.fixture
def temp_session_dir():
    """Create temporary directory for session files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def session_manager(temp_session_dir):
    """Create SessionManager with temporary directory and active session."""
    session_file = temp_session_dir / ".session"
    key_file = temp_session_dir / ".enckey"

    def _init_with_temp(self, sf=".session"):
        self.root_path = temp_session_dir
        self.session_file_path = self.root_path / sf
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()
        self._encryption_key_cache = None

    with patch.object(SessionManager, "__init__", _init_with_temp):
        manager = SessionManager()

        # Create an active session with encryption key for tests
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_encryption_key_32_bytes___",
        }
        manager.create_session(user_data)

        yield manager

        if session_file.exists():
            session_file.unlink()
        if key_file.exists():
            key_file.unlink() 