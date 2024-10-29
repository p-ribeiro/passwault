import sqlite3
from enum import Enum
from typing import Tuple

import bcrypt

ROLES = {"admin": 1, "user": 2}


def get_connection(db="passwalt.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )"""
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_name TEXT NOT NULL,
            password TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """
    )

    conn.commit()
    conn.close()


def add_user(username: str, password: str, role: str) -> str | None:

    if role.lower() not in ROLES:
        return "This role is invalid"

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    query = f"""
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);
    """

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(query, (username, password_hash, ROLES[role.lower()]))
        conn.commit()
    except sqlite3.IntegrityError as ie:
        return f"User already exists"
    except Exception as e:
        return f"Error during insertion: {str(e)}"
    finally:
        conn.close()

    return None


def authenticate(username: str, password: str) -> str | int:

    query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user is None:
            return "User not found"

        user_id: int = user[0]
        password_hash: str = user[1]

        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            return user_id
        else:
            return "Authentication failed"
    except Exception as e:
        return f"Error found while autheticating user: {e}"
    finally:
        conn.close()


def authorization(username: str, required_role: str) -> str | None:

    query = f"""
        SELECT role FROM users WHERE username=?
    """

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, username)
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return "User not found"

    user_role = user[0]

    if required_role.lower() == user_role:
        return None
    else:
        return "Not authorized"


def get_user_id(username: str) -> int | str:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE username=?", (username))
        user_id: int = cursor.fetchone()[0]
    except Exception as e:
        return f"Error getting user_id: {e}"
    finally:
        conn.close()

    return user_id


def save_password(user_id: str, password: str, password_name: str) -> str | None:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO passwords (password_name, password, user_id) VALUES (?,?,?)",
            (password_name, password, user_id),
        )
        conn.commit()
    except Exception as e:
        return f"Error while saving password: {e}"
    finally:
        conn.close()
    return None


def get_password(user_id: str, password_name: str) -> str:

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM passwords WHERE password_name=? AND user_id=?", (password_name, user_id))

        password: str = cursor.fetchone()[0]
    except Exception as e:
        return f"Error while retrieving password: {e}"
    finally:
        conn.close()

    return password
