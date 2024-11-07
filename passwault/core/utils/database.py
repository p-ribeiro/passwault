import sqlite3

import bcrypt

from passwault.core.utils.local_types import Response

ROLES = {"admin": 1, "user": 2}


def get_connection(db="passwalt.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

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

    cursor.execute(query_create_users)
    cursor.execute(query_create_passwords)

    conn.commit()
    conn.close()


def add_user(username: str, password: str, role: str) -> Response:

    if role.lower() not in ROLES:
        return Response(False, "This role is invalid")

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
        return Response(False, f"User already exists")
    except Exception as e:
        return Response(False, f"Error during insertion: {str(e)}")
    finally:
        conn.close()

    return Response(True, None)


def authentication(username: str, password: str) -> Response:

    query = f"""
        SELECT user_id, password_hash FROM users WHERE username=?
    """

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user is None:
            return Response(False, "User not found")

        user_id: int = user[0]
        password_hash: str = user[1]

        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            return Response(True, user_id)
        else:
            return Response(False, "Authentication failed")
    except Exception as e:
        return Response(False, f"Error found while authenticating user: {e}")
    finally:
        conn.close()


def authorization(username: str, required_role: str) -> Response:

    query = f"""
        SELECT role FROM users WHERE username=?
    """

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return (False, "User not found")

    user_role = user[0]

    if required_role.lower() == user_role:
        return Response(True, None)
    else:
        return Response(False, "Not authorized")


def get_user_id(username: str) -> Response:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE username=?", (username,))
        user_id: int = cursor.fetchone()

        if user_id:
            return Response(True, user_id[0])
        else:
            return Response(False, "User not found")

    except Exception as e:
        return Response(False, f"Error getting user_id: {e}")
    finally:
        conn.close()


def get_role(username: str) -> Response:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT role FROM users WHERE username=?", (username,))
        user_role: int = cursor.fetchone()

        if user_role:
            return Response(True, user_role[0])
        else:
            return Response(False, "User not found")

    except Exception as e:
        return Response(False, f"Error getting user_role: {e}")
    finally:
        conn.close()


def save_password(user_id: int, password: str, password_name: str) -> Response:
    conn = get_connection()
    cursor = conn.cursor()

    query = "INSERT INTO passwords (password_name, password, user_id) VALUES (?,?,?)"
    try:
        cursor.execute(query, (password_name, password, user_id))
        conn.commit()
    except Exception as e:
        return Response(False, f"Error while saving password: {e}")
    finally:
        conn.close()
    return Response(True, None)


def get_password(user_id: str, password_name: str) -> Response:

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT password FROM passwords WHERE password_name=? AND user_id=?"
    try:
        cursor.execute(query, (password_name, user_id))
        password: str = cursor.fetchone()

        if password:
            return Response(True, password[0])
        else:
            return Response(False, "Password not found")
    except Exception as e:
        return Response(False, f"Error while retrieving password: {e}")
    finally:
        conn.close()
