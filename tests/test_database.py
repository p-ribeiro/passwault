import sqlite3
from unittest import mock

import pytest
from pytest import MonkeyPatch

from vault.core.utils.database import (add_user, authenticate, authorization,
                                       get_connection, get_user_id, init_db,
                                       save_password)


@pytest.fixture
def mock_get_connection(monkeypatch):
    print("hhhewolrhiowerhoeiwrhioheowihrio")
    mock_conn = mock.MagicMock()

    mock_cursor = mock.MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    monkeypatch.setattr("vault.core.utils.database.get_connection", lambda db="passwault.db": mock_conn)

    yield mock_conn, mock_cursor


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


def test_add_user(mock_get_connection, mocker):
    _, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)

    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_args = ('test_user', mock_password_hash, 1)

    result = add_user("test_user", "test_password", "admin")
    assert mock_cursor.execute.called
    assert mock_cursor.execute.call_count == 1
    assert result == None

    expected_calls = [mock.call(expected_query, expected_args)]
    mock_cursor.execute.assert_has_calls(expected_calls)


def test_add_user_integrity_exception(mock_get_connection, mocker):
    _, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)
    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_args = ('test_user', mock_password_hash, 1)

    mock_cursor.execute.side_effect = sqlite3.IntegrityError("Unique contraint failed")

    result = add_user("test_user", "test_password", "admin")
    assert mock_cursor.execute.called
    assert mock_cursor.execute.call_count == 1
    assert result == "User already exists"

    expected_calls = [mock.call(expected_query, expected_args)]
    mock_cursor.execute.assert_has_calls(expected_calls)


def test_add_user_integrity_exception(mock_get_connection, mocker):
    _, mock_cursor = mock_get_connection

    mock_password_hash = b'mocked_hash_balue'
    mocker.patch('vault.core.utils.database.bcrypt.hashpw', return_value=mock_password_hash)
    expected_query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """
    expected_args = ('test_user', mock_password_hash, 1)

    mock_cursor.execute.side_effect = Exception("An exception")

    result = add_user("test_user", "test_password", "admin")
    assert mock_cursor.execute.called
    assert mock_cursor.execute.call_count == 1
    assert result == f"Error during insertion: An exception"

    expected_calls = [mock.call(expected_query, expected_args)]
    mock_cursor.execute.assert_has_calls(expected_calls)
