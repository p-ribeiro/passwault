from src.passwault.core.utils import enums
import pytest
from src.passwault.core.utils.database import IntegrityError, SQLiteConnector


@pytest.fixture
def connector():
    db = SQLiteConnector(":memory:")
    db.init_db()
    yield db
    db.close()


def test_connect_and_placeholder(connector):
    assert connector.connection is not None
    assert connector.get_placeholder_symbol() == "?"


def test_init_db_creates_tables(connector):
    connector.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = set(name for (name,) in connector.cursor.fetchall())
    assert "users" in tables
    assert "passwords" in tables


def test_insert_and_fetch_user(connector):
    query = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
    connector.execute_query(query, ("johndoe", "pwhash", enums.ROLES["admin"]))
    user = connector.fetch_one("SELECT * FROM users WHERE username = ?", ("johndoe",))
    assert user == (1, "johndoe", "pwhash", 1)


def test_fetch_all_returns_multiple_rows(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("jane", "janegotagun", enums.ROLES["user"]))

    users = connector.fetch_all("SELECT * FROM users")

    assert len(users) == 2


def test_integrity_error_mapping(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))

    with pytest.raises(IntegrityError) as exc:
        connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "anotherpw", enums.ROLES["user"]))
    assert "already exists" in str(exc.value)
