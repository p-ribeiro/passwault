from datetime import datetime, timezone
from src.passwault.core.commands.authenticator import register, login
from unittest.mock import patch, MagicMock

fake_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_register_success(mock_logger, mock_get_password):
    mock_ctx = MagicMock()
    mock_user_repo = MagicMock()
    mock_user_repo.check_if_username_exists.return_value.ok = True
    mock_user_repo.check_if_username_exists.return_value.result = False
    mock_user_repo.register.return_value.ok = True
    mock_ctx.user_repo = mock_user_repo

    register("johndoe", None, "user", mock_ctx)

    mock_user_repo.check_if_username_exists.assert_called_once_with("johndoe")
    mock_user_repo.register.assert_called_once_with("johndoe", "fake_password", "user")
    mock_logger.info.assert_called_with("User created.")


@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_register_username_taken(mock_logger, mock_get_password):
    mock_ctx = MagicMock()
    mock_user_repo = MagicMock()
    mock_user_repo.check_if_username_exists.return_value.ok = True
    mock_user_repo.check_if_username_exists.return_value.result = True
    mock_user_repo.register.return_value.ok = True

    mock_ctx.user_repo = mock_user_repo

    register("johndoe", None, "user", mock_ctx)

    mock_user_repo.check_if_username_exists.assert_called_once_with("johndoe")
    mock_logger.info.assert_called_with("This username is already taken. Please provide another.")
    mock_user_repo.register.assert_not_called()


@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_register_fail(mock_logger, mock_get_password):
    mock_ctx = MagicMock()
    mock_user_repo = MagicMock()
    mock_user_repo.check_if_username_exists.return_value.ok = True
    mock_user_repo.check_if_username_exists.return_value.result = False
    mock_user_repo.register.return_value.ok = False
    mock_user_repo.register.return_value.result = "Error while registering"

    mock_ctx.user_repo = mock_user_repo
    register("johndoe", None, "user", mock_ctx)

    mock_user_repo.check_if_username_exists.assert_called_once_with("johndoe")
    mock_user_repo.register.assert_called_once_with("johndoe", "fake_password", "user")
    mock_logger.error.assert_called_with("Error while registering")


@patch("src.passwault.core.commands.authenticator.datetime")
@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_login_success(mock_logger, mock_get_password, mock_datetime):
    mock_ctx = MagicMock()
    
    mock_connector = MagicMock()
    mock_session_manager = MagicMock()
    mock_session_manager.connector = mock_connector

    mock_datetime.now.return_value = fake_time

    mock_user_repo = MagicMock()
    mock_user_repo.authentication.return_value.ok = True
    mock_user_repo.authentication.return_value.result = 13
    mock_user_repo.get_role.return_value.ok = True
    mock_user_repo.get_role.return_value.result = 1
    
    mock_ctx.session_manager = mock_session_manager
    mock_ctx.user_repo = mock_user_repo

    login("johndoe", None, mock_ctx)

    mock_user_repo.authentication.assert_called_once_with("johndoe", "fake_password")
    mock_user_repo.get_role.assert_called_once()
    mock_session_manager.create_session.assert_called_once_with({"id": 13, "role": 1, "time": fake_time.isoformat()})
    mock_logger.info.assert_called_once_with("User logged in")


@patch("src.passwault.core.commands.authenticator.datetime")
@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_login_not_authenticated(mock_logger, mock_get_password, mock_datetime):
    mock_ctx = MagicMock()
    mock_connector = MagicMock()
    mock_session_manager = MagicMock()
    mock_session_manager.connector = mock_connector

    mock_datetime.now.return_value = fake_time

    mock_user_repo = MagicMock()
    mock_user_repo.authentication.return_value.ok = False
    mock_user_repo.authentication.return_value.result = "Authentication failed"

    mock_ctx.user_repo = mock_user_repo
    mock_ctx.session_manager = mock_session_manager


    login("johndoe", None, mock_ctx)

    mock_user_repo.authentication.assert_called_once_with("johndoe", "fake_password")
    mock_user_repo.get_role.assert_not_called()
    mock_session_manager.create_session.assert_not_called()
    mock_logger.error.assert_called_once_with("Authentication failed")


@patch("src.passwault.core.commands.authenticator.datetime")
@patch("src.passwault.core.commands.authenticator.get_password_with_mask", return_value="fake_password")
@patch("src.passwault.core.commands.authenticator.Logger")
def test_login_role_not_found(mock_logger, mock_get_password, mock_datetime):
    mock_ctx = MagicMock()
    mock_connector = MagicMock()
    mock_session_manager = MagicMock()
    mock_session_manager.connector = mock_connector

    mock_datetime.now.return_value = fake_time

    mock_user_repo = MagicMock()
    mock_user_repo.authentication.return_value.ok = True
    mock_user_repo.authentication.return_value.result = 13
    mock_user_repo.get_role.return_value.ok = False
    mock_user_repo.get_role.return_value.result = "Role not found"

    mock_ctx.user_repo = mock_user_repo
    mock_ctx.session_manager = mock_session_manager

    login("johndoe", None, mock_ctx)

    mock_user_repo.authentication.assert_called_once_with("johndoe", "fake_password")
    mock_user_repo.get_role.assert_called_once()
    mock_session_manager.create_session.assert_not_called()
    mock_logger.error.assert_called_once_with("Role not found")
