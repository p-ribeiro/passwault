"""Unit tests for CLI interface.

Tests command parsing, argument validation, and command routing
for all Passwault CLI commands.
"""

import io
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from passwault.core.cli import cli
from passwault.core.utils.session_manager import SessionManager


@pytest.fixture
def temp_session_dir():
    """Create temporary directory for session files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def session_manager(temp_session_dir):
    """Create SessionManager with temporary directory."""

    def _init_with_temp(self, sf=".session"):
        self.root_path = temp_session_dir
        self.session_file_path = self.root_path / sf
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()
        self._encryption_key_cache = None

    with patch.object(SessionManager, "__init__", _init_with_temp):
        manager = SessionManager()
        yield manager


class TestAuthenticationCommands:
    """Test suite for authentication CLI commands."""

    @patch("passwault.core.cli.register")
    def test_register_with_all_arguments(self, mock_register, session_manager):
        """Test register command with all arguments provided."""
        test_args = [
            "auth",
            "register",
            "-u",
            "johndoe",
            "-p",
            "SecurePass123!",
            "-e",
            "john@example.com",
        ]
        cli(test_args, session_manager)

        mock_register.assert_called_once_with(
            "johndoe", "SecurePass123!", "john@example.com", session_manager
        )

    @patch("passwault.core.cli.register")
    def test_register_without_password(self, mock_register, session_manager):
        """Test register command without password (will prompt)."""
        test_args = ["auth", "register", "-u", "johndoe"]
        cli(test_args, session_manager)

        mock_register.assert_called_once_with("johndoe", None, None, session_manager)

    def test_register_without_username(self, session_manager):
        """Test register command fails without username."""
        test_args = ["auth", "register", "-p", "password"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    @patch("passwault.core.cli.login")
    def test_login_with_all_arguments(self, mock_login, session_manager):
        """Test login command with all arguments."""
        test_args = ["auth", "login", "-u", "johndoe", "-p", "SecurePass123!"]
        cli(test_args, session_manager)

        mock_login.assert_called_once_with("johndoe", "SecurePass123!", session_manager)

    @patch("passwault.core.cli.login")
    def test_login_without_password(self, mock_login, session_manager):
        """Test login command without password (will prompt)."""
        test_args = ["auth", "login", "-u", "johndoe"]
        cli(test_args, session_manager)

        mock_login.assert_called_once_with("johndoe", None, session_manager)

    def test_login_without_username(self, session_manager):
        """Test login command fails without username."""
        test_args = ["auth", "login", "-p", "password"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    @patch("passwault.core.cli.logout")
    def test_logout(self, mock_logout, session_manager):
        """Test logout command."""
        test_args = ["auth", "logout"]
        cli(test_args, session_manager)

        mock_logout.assert_called_once_with(session_manager)


class TestPasswordGenerationCommands:
    """Test suite for password generation CLI commands."""

    @patch("passwault.core.cli.generate_password")
    def test_generate_with_all_options(self, mock_generate, session_manager):
        """Test generate command with all character types enabled."""
        test_args = ["generate", "-l", "30"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=30, has_symbols=True, has_digits=True, has_uppercase=True
        )

    @patch("passwault.core.cli.generate_password")
    def test_generate_with_default_length(self, mock_generate, session_manager):
        """Test generate command with default length."""
        test_args = ["generate"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=16, has_symbols=True, has_digits=True, has_uppercase=True
        )

    @patch("passwault.core.cli.generate_password")
    def test_generate_no_symbols(self, mock_generate, session_manager):
        """Test generate command excluding symbols."""
        test_args = ["generate", "--no-symbols"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=16, has_symbols=False, has_digits=True, has_uppercase=True
        )

    @patch("passwault.core.cli.generate_password")
    def test_generate_no_digits(self, mock_generate, session_manager):
        """Test generate command excluding digits."""
        test_args = ["generate", "--no-digits"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=16, has_symbols=True, has_digits=False, has_uppercase=True
        )

    @patch("passwault.core.cli.generate_password")
    def test_generate_no_uppercase(self, mock_generate, session_manager):
        """Test generate command excluding uppercase."""
        test_args = ["generate", "--no-uppercase"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=16, has_symbols=True, has_digits=True, has_uppercase=False
        )

    @patch("passwault.core.cli.generate_password")
    def test_generate_custom_length_and_exclusions(
        self, mock_generate, session_manager
    ):
        """Test generate command with custom length and exclusions."""
        test_args = ["generate", "-l", "20", "--no-symbols", "--no-digits"]
        cli(test_args, session_manager)

        mock_generate.assert_called_once_with(
            password_length=20, has_symbols=False, has_digits=False, has_uppercase=True
        )


class TestPasswordManagementCommands:
    """Test suite for password management CLI commands."""

    @patch("passwault.core.cli.save_password")
    def test_save_password_minimal(self, mock_save, session_manager):
        """Test save command with minimal required arguments."""
        test_args = ["save", "-n", "github", "-p", "secret123"]
        cli(test_args, session_manager)

        mock_save.assert_called_once_with(
            resource_name="github",
            password="secret123",
            username=None,
            website=None,
            description=None,
            tags=None,
            session_manager=session_manager,
        )

    @patch("passwault.core.cli.save_password")
    def test_save_password_all_fields(self, mock_save, session_manager):
        """Test save command with all optional fields."""
        test_args = [
            "save",
            "-n",
            "github",
            "-p",
            "secret123",
            "-u",
            "johndoe",
            "-w",
            "https://github.com",
            "-d",
            "My GitHub account",
            "-t",
            "work,dev",
        ]
        cli(test_args, session_manager)

        mock_save.assert_called_once_with(
            resource_name="github",
            password="secret123",
            username="johndoe",
            website="https://github.com",
            description="My GitHub account",
            tags="work,dev",
            session_manager=session_manager,
        )

    def test_save_password_missing_resource_name(self, session_manager):
        """Test save command fails without resource name."""
        test_args = ["save", "-p", "secret123"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    def test_save_password_missing_password(self, session_manager):
        """Test save command fails without password."""
        test_args = ["save", "-n", "github"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    @patch("passwault.core.cli.load_password")
    def test_load_password_by_resource_name(self, mock_load, session_manager):
        """Test load command by resource name."""
        test_args = ["load", "-n", "github"]
        cli(test_args, session_manager)

        mock_load.assert_called_once_with(
            resource_name="github",
            username=None,
            all_passwords=False,
            session_manager=session_manager,
        )

    @patch("passwault.core.cli.load_password")
    def test_load_password_by_username(self, mock_load, session_manager):
        """Test load command by username."""
        test_args = ["load", "-u", "johndoe"]
        cli(test_args, session_manager)

        mock_load.assert_called_once_with(
            resource_name=None,
            username="johndoe",
            all_passwords=False,
            session_manager=session_manager,
        )

    @patch("passwault.core.cli.load_password")
    def test_load_all_passwords(self, mock_load, session_manager):
        """Test load command for all passwords."""
        test_args = ["load", "-a"]
        cli(test_args, session_manager)

        mock_load.assert_called_once_with(
            resource_name=None,
            username=None,
            all_passwords=True,
            session_manager=session_manager,
        )

    @patch("passwault.core.cli.update_password")
    def test_update_password_minimal(self, mock_update, session_manager):
        """Test update command with minimal arguments."""
        test_args = ["update", "-n", "github", "-p", "newsecret456"]
        cli(test_args, session_manager)

        mock_update.assert_called_once_with(
            resource_name="github",
            new_password="newsecret456",
            username=None,
            website=None,
            description=None,
            tags=None,
            session_manager=session_manager,
        )

    @patch("passwault.core.cli.update_password")
    def test_update_password_with_metadata(self, mock_update, session_manager):
        """Test update command with metadata updates."""
        test_args = [
            "update",
            "-n",
            "github",
            "-p",
            "newsecret456",
            "-u",
            "newuser",
            "-w",
            "https://github.com/new",
        ]
        cli(test_args, session_manager)

        mock_update.assert_called_once_with(
            resource_name="github",
            new_password="newsecret456",
            username="newuser",
            website="https://github.com/new",
            description=None,
            tags=None,
            session_manager=session_manager,
        )

    def test_update_password_missing_resource_name(self, session_manager):
        """Test update command fails without resource name."""
        test_args = ["update", "-p", "newsecret"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    @patch("passwault.core.cli.delete_password")
    def test_delete_password(self, mock_delete, session_manager):
        """Test delete command."""
        test_args = ["delete", "-n", "github"]
        cli(test_args, session_manager)

        mock_delete.assert_called_once_with(
            resource_name="github", session_manager=session_manager
        )

    def test_delete_password_missing_resource_name(self, session_manager):
        """Test delete command fails without resource name."""
        test_args = ["delete"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2


class TestImagepassCommands:
    """Test suite for imagepass CLI commands."""

    @patch("passwault.core.cli.handle_imagepass")
    @patch("passwault.core.cli.valid_image_file", lambda x: x)
    def test_imagepass_encode(self, mock_imagepass, session_manager):
        """Test imagepass encode command."""
        test_args = ["imagepass", "encode", "test.png", "-p", "secret"]
        cli(test_args, session_manager)

        mock_imagepass.assert_called_once()
        args = mock_imagepass.call_args[0][0]
        assert args.option == "encode"
        assert args.image_path == "test.png"
        assert args.password == "secret"

    @patch("passwault.core.cli.handle_imagepass")
    @patch("passwault.core.cli.valid_image_file", lambda x: x)
    def test_imagepass_decode(self, mock_imagepass, session_manager):
        """Test imagepass decode command."""
        test_args = ["imagepass", "decode", "test.png"]
        cli(test_args, session_manager)

        mock_imagepass.assert_called_once()
        args = mock_imagepass.call_args[0][0]
        assert args.option == "decode"
        assert args.image_path == "test.png"

    def test_imagepass_missing_image_path(self, session_manager):
        """Test imagepass fails without image path."""
        test_args = ["imagepass", "encode"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2

    def test_imagepass_invalid_option(self, session_manager):
        """Test imagepass fails with invalid option."""
        test_args = ["imagepass", "invalid", "test.png"]

        with patch("sys.stderr", io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                cli(test_args, session_manager)

            assert exc_info.value.code == 2


class TestCLIIntegration:
    """Integration tests for CLI."""

    def test_no_command_shows_help(self, session_manager):
        """Test that running with no command shows help."""
        with patch("sys.stdout", io.StringIO()):
            cli([], session_manager)

            # Help text should be printed
            # Note: This may not capture help output due to argparse internals
            # Main point is it doesn't crash

    def test_session_manager_passed_to_commands(self, session_manager):
        """Test that session_manager is properly passed to all commands."""
        with patch("passwault.core.cli.login") as mock_login:
            test_args = ["auth", "login", "-u", "test"]
            cli(test_args, session_manager)

            # Verify session_manager was passed
            call_args = mock_login.call_args
            assert call_args[0][2] == session_manager

    def test_keyboard_interrupt_handling(self, session_manager):
        """Test that Ctrl+C is handled gracefully."""
        with patch("passwault.core.cli.login", side_effect=KeyboardInterrupt()):
            test_args = ["auth", "login", "-u", "test"]
            # Should not raise exception
            cli(test_args, session_manager)
