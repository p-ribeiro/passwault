import pytest


from src.passwault.core.utils.database import SQLiteConnector


@pytest.fixture
def connector():
    db = SQLiteConnector(":memory:")
    db.init_db()
    db.connect()
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
