from pytest_mock import MockerFixture

from vault.core.password_ops import load_pw, save_pw


def test_save_pw_success(mocker: MockerFixture):
    mocked_saved_password = mocker.patch('vault.core.password_ops.save_password', return_value=None)
    mocked_logger_info = mocker.patch('vault.core.utils.logger.Logger.info')
    mocked_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

    save_pw(21, "test_password", "test_password_identifier")

    mocked_saved_password.assert_called_once_with(21, "test_password", "test_password_identifier")
    mocked_logger_info.assert_called_once_with("Inserted with success")
    mocked_logger_error.assert_not_called()


def test_save_pw_failure(mocker: MockerFixture):
    mocked_saved_password = mocker.patch('vault.core.password_ops.save_password', return_value="Error saving password")
    mocked_logger_info = mocker.patch('vault.core.utils.logger.Logger.info')
    mocked_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

    save_pw(21, "test_password", "test_password_identifier")

    mocked_saved_password.assert_called_once_with(21, "test_password", "test_password_identifier")
    mocked_logger_info.assert_not_called()
    mocked_logger_error.assert_called_once_with("Error saving password")


def test_load_pw_success(mocker: MockerFixture, capfd):
    mocked_get_password = mocker.patch('vault.core.password_ops.get_password', return_value="my_password")
    mocked_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

    load_pw(21, 'password_identifier')
    captured = capfd.readouterr()
    output = captured.out

    mocked_get_password.assert_called_once_with(21, 'password_identifier')
    mocked_logger_error.assert_not_called()

    assert output.strip() == "Password for password_identifier: my_password"


def test_load_pw_failure(mocker: MockerFixture):
    mocked_get_password = mocker.patch('vault.core.password_ops.get_password', return_value="Error getting password")
    mocked_logger_error = mocker.patch('vault.core.utils.logger.Logger.error')

    load_pw(21, 'password_identifier')

    mocked_get_password.assert_called_once_with(21, 'password_identifier')
    mocked_logger_error.assert_called_once_with("Error getting password")
