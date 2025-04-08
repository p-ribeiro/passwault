# from unittest.mock import Mock

# import pytest
# from pytest_mock import MockerFixture

# from passwault.core.commands.authenticator import login, register


# def test_register_success(mocker: MockerFixture):
#     mock_add_user = mocker.patch('vault.core.authenticator.add_user', return_value=None)
#     mock_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

#     register('test_user', "test_password", "admin")

#     mock_add_user.assert_called_once_with("test_user", "test_password", "admin")
#     mock_logger_error.assert_not_called()


# def test_register_failure(mocker: MockerFixture):

#     mock_add_user = mocker.patch('vault.core.authenticator.add_user', return_value="User already exists")
#     mock_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

#     register('test_user', "test_password", "admin")

#     mock_add_user.assert_called_once_with("test_user", "test_password", "admin")
#     mock_logger_error.assert_called_once_with("User already exists")


# def test_login_success(mocker: MockerFixture):
#     mock_authenticate = mocker.patch('vault.core.authenticator.authentication', return_value=21)

#     mock_callback = Mock()

#     login("test_user", "test_password", mock_callback)

#     mock_authenticate.assert_called_once_with("test_user", "test_password")
#     mock_callback.assert_called_once_with(21)


# def test_login_failure(mocker: MockerFixture):
#     mock_authenticate = mocker.patch(
#         'vault.core.authenticator.authentication', return_value="Error with authentication"
#     )
#     mock_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')
#     mock_callback = Mock()

#     login("test_user", "test_password", mock_callback)

#     mock_authenticate.assert_called_once_with("test_user", "test_password")
#     mock_logger_error.assert_called_once_with('Error with authentication')
#     mock_callback.assert_not_called()
