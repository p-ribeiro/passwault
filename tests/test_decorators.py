"""Unit tests for authentication decorators.

Tests the @require_auth decorator for protecting password operations.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from passwault.core.utils.decorators import require_auth
from passwault.core.utils.session_manager import SessionManager


@pytest.fixture
def temp_session_dir():
    """Create temporary directory for session files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def session_manager(temp_session_dir):
    """Create SessionManager with temporary directory."""
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
        yield manager

        if session_file.exists():
            session_file.unlink()
        if key_file.exists():
            key_file.unlink()


class TestRequireAuthDecorator:
    """Test suite for @require_auth decorator."""

    def test_decorator_allows_execution_when_logged_in(self, session_manager):
        """Test decorator allows execution when user is logged in."""

        @require_auth
        def protected_function(arg1, arg2, session_manager):
            return f"{arg1}_{arg2}"

        # Create session with encryption key
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        # Function should execute
        result = protected_function("hello", "world", session_manager)
        assert result == "hello_world"

    def test_decorator_blocks_when_not_logged_in(self, session_manager):
        """Test decorator blocks execution when user is not logged in."""

        @require_auth
        def protected_function(session_manager):
            return "success"

        # No session created
        result = protected_function(session_manager)
        assert result is None

    def test_decorator_blocks_when_encryption_key_missing(self, session_manager):
        """Test decorator blocks when encryption key is missing."""

        @require_auth
        def protected_function(session_manager):
            return "success"

        # Create session without encryption key
        session_manager.session = {
            "user_id": 1,
            "username": "testuser",
            "timestamp": "2024-01-01T00:00:00",
        }
        session_manager._encryption_key_cache = None

        result = protected_function(session_manager)
        assert result is None

    def test_decorator_with_kwargs(self, session_manager):
        """Test decorator works with keyword arguments."""

        @require_auth
        def protected_function(arg1, session_manager=None):
            return f"processed_{arg1}"

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result = protected_function("data", session_manager=session_manager)
        assert result == "processed_data"

    def test_decorator_with_positional_args(self, session_manager):
        """Test decorator finds session_manager in positional args."""

        @require_auth
        def protected_function(arg1, arg2, session_manager):
            return arg1 + arg2

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result = protected_function(5, 10, session_manager)
        assert result == 15

    def test_decorator_handles_missing_session_manager(self):
        """Test decorator handles missing session_manager gracefully."""

        @require_auth
        def protected_function(arg1, arg2):
            return arg1 + arg2

        # Call without session_manager
        result = protected_function(5, 10)
        assert result is None

    def test_decorator_handles_invalid_session_manager_type(self):
        """Test decorator handles invalid session_manager type."""

        @require_auth
        def protected_function(session_manager):
            return "success"

        # Pass wrong type
        result = protected_function("not_a_session_manager")
        assert result is None

    def test_decorator_preserves_function_metadata(self):
        """Test decorator preserves original function metadata."""

        @require_auth
        def example_function(session_manager):
            """Example function docstring."""
            return "result"

        assert example_function.__name__ == "example_function"
        assert example_function.__doc__ == "Example function docstring."

    def test_decorator_with_return_values(self, session_manager):
        """Test decorator preserves return values from decorated function."""

        @require_auth
        def get_user_data(session_manager):
            return {"user_id": 1, "username": "testuser"}

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result = get_user_data(session_manager)
        assert result == {"user_id": 1, "username": "testuser"}

    def test_decorator_with_exceptions(self, session_manager):
        """Test decorator allows exceptions to propagate."""

        @require_auth
        def function_that_raises(session_manager):
            raise ValueError("Test error")

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        with pytest.raises(ValueError, match="Test error"):
            function_that_raises(session_manager)

    def test_decorator_with_multiple_arguments(self, session_manager):
        """Test decorator with complex argument structure."""

        @require_auth
        def complex_function(a, b, c=None, d=None, session_manager=None):
            return f"{a}_{b}_{c}_{d}"

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result = complex_function(
            "arg1", "arg2", c="kwarg1", d="kwarg2", session_manager=session_manager
        )
        assert result == "arg1_arg2_kwarg1_kwarg2"

    def test_decorator_session_expiration(self, session_manager):
        """Test decorator blocks after session expiration."""

        @require_auth
        def protected_function(session_manager):
            return "success"

        # Create session
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        # Verify it works
        assert protected_function(session_manager) == "success"

        # Expire session manually
        session_manager.logout()

        # Should now be blocked
        result = protected_function(session_manager)
        assert result is None


class TestRequireAuthIntegration:
    """Integration tests for @require_auth decorator."""

    def test_decorator_with_real_password_operations(self, session_manager):
        """Test decorator protects password-like operations."""

        @require_auth
        def save_password(password_name, password, session_manager):
            user_id = session_manager.get_user_id()
            encryption_key = session_manager.get_encryption_key()
            return {
                "user_id": user_id,
                "password_name": password_name,
                "encrypted": True,
            }

        # Try without login
        result = save_password("github", "mypassword123", session_manager)
        assert result is None

        # Login and try again
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result = save_password("github", "mypassword123", session_manager)
        assert result is not None
        assert result["user_id"] == 1
        assert result["password_name"] == "github"
        assert result["encrypted"] is True

    def test_decorator_chain_multiple_operations(self, session_manager):
        """Test decorator protects multiple chained operations."""

        @require_auth
        def operation1(session_manager):
            return "op1_result"

        @require_auth
        def operation2(prev_result, session_manager):
            return f"{prev_result}_op2_result"

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        result1 = operation1(session_manager)
        result2 = operation2(result1, session_manager)

        assert result1 == "op1_result"
        assert result2 == "op1_result_op2_result"

    def test_decorator_logout_blocks_subsequent_calls(self, session_manager):
        """Test decorator blocks calls after logout."""

        @require_auth
        def protected_operation(session_manager):
            return "success"

        user_data = {
            "user_id": 1,
            "username": "testuser",
            "encryption_key": b"test_key_32_bytes_for_testing",
        }
        session_manager.create_session(user_data)

        # First call succeeds
        assert protected_operation(session_manager) == "success"

        # Logout
        session_manager.logout()

        # Second call blocked
        assert protected_operation(session_manager) is None
