import sqlite3
from unittest import mock

import bcrypt
import pytest
from pytest import MonkeyPatch

from passwault.core.utils.database import (add_user, authentication,
                                           authorization, get_connection,
                                           get_password, get_user_id, init_db,
                                           save_password)


@pytest.fixture
def mock_get_connection(monkeypatch):
    mock_conn = mock.MagicMock()

    mock_cursor = mock.MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    monkeypatch.setattr("vault.core.utils.database.get_connection", lambda db="passwault.db": mock_conn)

    yield mock_conn, mock_cursor


def test_get_connection():
    with mock.patch('vault.core.utils.database.sqlite3.connect') as mock_connect:
        mock_conn = mock.MagicMock()
        # mock_cursor = mock.MagicMock()

        mock_connect.return_value = mock_conn

        conn = get_connection('test.db')

        mock_connect.assert_called_once_with("test.db")
        mock_conn.execute.assert_called_once_with("PRAGMA foreign_keys = ON")
        assert conn == mock_conn


def test_init_db(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection

    init_db()

    assert mock_cursor.execute.called
    assert mock_cursor.execute.call_count == 2

    query_create_users = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )"""
    query_create_passwords = """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_name TEXT NOT NULL,
            password TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )"""

    expected_calls = [mock.call(query_create_users), mock.call(query_create_passwords)]

    mock_cursor.execute.assert_has_calls(expected_calls, any_order=False)
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_add_user_success(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)

    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_params = ('test_user', mock_password_hash, 1)

    result = add_user("test_user", "test_password", "admin")

    assert result == None
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_add_user_invalid_role():
    result = add_user('teste_user', 'test_password', 'not_a_role')
    assert result == "This role is invalid"


def test_add_user_integrity_exception(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)
    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_params = ('test_user', mock_password_hash, 1)

    mock_cursor.execute.side_effect = sqlite3.IntegrityError("Unique contraint failed")

    result = add_user("test_user", "test_password", "admin")

    assert result == "User already exists"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_add_user_exception(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)
    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_params = ('test_user', mock_password_hash, 1)

    mock_cursor.execute.side_effect = Exception("An exception")

    result = add_user("test_user", "test_password", "admin")

    assert result == f"Error during insertion: An exception"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_authentication_success(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_username = "username_test"
    mock_password = "password_test"
    mock_password_hash = bcrypt.hashpw(mock_password.encode('utf-8'), bcrypt.gensalt())

    expected_query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = [1, mock_password_hash]

    result = authentication(mock_username, mock_password)

    assert result == 1
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_authentication_failed(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_username = "username_test"
    mock_password = "password_test"
    mock_password_hash = bcrypt.hashpw('real_password'.encode('utf-8'), bcrypt.gensalt())

    expected_query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = [1, mock_password_hash]

    result = authentication(mock_username, mock_password)

    assert result == "Authentication failed"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_authentication_user_not_found(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_username = "username_test"
    mock_password = "password_test"

    expected_query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = None

    result = authentication(mock_username, mock_password)

    assert result == "User not found"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_authentication_exception(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection

    mock_username = "username_test"
    mock_password = "password_test"
    mock_password_hash = bcrypt.hashpw('real_password'.encode('utf-8'), bcrypt.gensalt())

    expected_query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """
    expected_params = (mock_username,)
    mock_cursor.execute.side_effect = Exception("Database error")

    mock_cursor.fetchone.return_value = [1, mock_password_hash]

    result = authentication(mock_username, mock_password)

    assert result == "Error found while authenticating user: Database error"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_authorization_success(mock_get_connection, mocker):

    _, mock_cursor = mock_get_connection
    mock_username = "username_test"
    mock_role = "admin"

    expected_query = f"""
        SELECT role FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = [mock_role]

    result = authorization(mock_username, mock_role)

    assert result == None

    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_cursor.fetchone.assert_called_once()


def test_authorization_fail_role(mock_get_connection, mocker):
    _, mock_cursor = mock_get_connection
    mock_username = "username_test"
    mock_role = "admin"
    mock_role_db = "user"

    expected_query = f"""
        SELECT role FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = [mock_role_db]

    result = authorization(mock_username, mock_role)

    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_cursor.fetchone.assert_called_once()

    assert result == "Not authorized"


def test_authorization_user_not_found(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection
    mock_username = "username_test"
    mock_role = "admin"
    mock_role_db = "user"

    expected_query = f"""
        SELECT role FROM users WHERE username=?
    """
    expected_params = (mock_username,)

    mock_cursor.fetchone.return_value = None

    result = authorization(mock_username, mock_role)

    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_cursor.fetchone.assert_called_once()
    mock_conn.close.assert_called_once()
    assert result == "User not found"


def test_get_user_id_success(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection
    mock_username = "username_test"

    expected_query = "SELECT user_id FROM users WHERE username=?"
    expected_params = (mock_username,)
    mock_cursor.fetchone.return_value = 1

    result = get_user_id(mock_username)

    assert result == 1
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_get_user_id_user_not_found(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection
    mock_username = "username_test"

    expected_query = "SELECT user_id FROM users WHERE username=?"
    expected_params = (mock_username,)
    mock_cursor.fetchone.return_value = None

    result = get_user_id(mock_username)

    assert result == "User not found"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_get_user_id_exception(mock_get_connection, mocker):
    mock_conn, mock_cursor = mock_get_connection
    mock_username = "username_test"

    expected_query = "SELECT user_id FROM users WHERE username=?"
    expected_params = (mock_username,)
    mock_cursor.fetchone.side_effect = Exception("Error retrieving value")

    result = get_user_id(mock_username)

    assert result == "Error getting user_id: Error retrieving value"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_save_password_success(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection
    mock_user_id = 1
    mock_password = "password_test"
    mock_password_name = "password_name_test"

    expected_query = "INSERT INTO passwords (password_name, password, user_id) VALUES (?,?,?)"
    expected_params = (mock_password_name, mock_password, mock_user_id)

    result = save_password(mock_user_id, mock_password, mock_password_name)

    assert result == None
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_save_password_exception(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection
    mock_user_id = 1
    mock_password = "password_test"
    mock_password_name = "password_name_test"

    expected_query = "INSERT INTO passwords (password_name, password, user_id) VALUES (?,?,?)"
    expected_params = (mock_password_name, mock_password, mock_user_id)
    mock_conn.commit.side_effect = Exception("Error saving to database")

    result = save_password(mock_user_id, mock_password, mock_password_name)

    assert result == "Error while saving password: Error saving to database"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_get_password_success(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection
    mock_user_id = 1
    mock_password_name = "password_name_test"

    expected_query = "SELECT password FROM passwords WHERE password_name=? AND user_id=?"
    expected_params = (mock_password_name, mock_user_id)
    mock_cursor.fetchone.return_value = "password_test"

    result = get_password(mock_user_id, mock_password_name)
    assert result == "password_test"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_get_password_not_found(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection
    mock_user_id = 1
    mock_password_name = "password_name_test"

    expected_query = "SELECT password FROM passwords WHERE password_name=? AND user_id=?"
    expected_params = (mock_password_name, mock_user_id)
    mock_cursor.fetchone.return_value = None

    result = get_password(mock_user_id, mock_password_name)
    assert result == "Password not found"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()


def test_get_password_exception(mock_get_connection):
    mock_conn, mock_cursor = mock_get_connection
    mock_user_id = 1
    mock_password_name = "password_name_test"

    expected_query = "SELECT password FROM passwords WHERE password_name=? AND user_id=?"
    expected_params = (mock_password_name, mock_user_id)
    mock_cursor.fetchone.side_effect = Exception("Error getting value from database")

    result = get_password(mock_user_id, mock_password_name)
    assert result == "Error while retrieving password: Error getting value from database"
    mock_cursor.execute.assert_called_once_with(expected_query, expected_params)
    mock_conn.close.assert_called_once()
