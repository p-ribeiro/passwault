from src.passwault.core.utils import enums
from src.passwault.core.utils.database import SQLiteConnector
from src.passwault.core.utils.user_repository import UserRepository
import pytest


@pytest.fixture
def connector():
    db = SQLiteConnector(":memory:")
    db.init_db()
    yield db
    db.close()


def create_default_user(connector, role="user"):
    user_repo = UserRepository(connector)
    response = user_repo.register(username="johndoe", password="this_is_my_password", role=role)
    assert response.ok is True

    return user_repo


def test_check_if_username_exists(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))
    user_repo = UserRepository(connector)
    response = user_repo.check_if_username_exists("johndoe")

    assert response.ok is True
    assert response.result is True


def test_check_if_username_not_exists(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))
    user_repo = UserRepository(connector)
    response = user_repo.check_if_username_exists("jane")

    assert response.ok is True
    assert response.result is False


def test_register(connector):
    user_repo = create_default_user(connector)
    user = connector.fetch_one("SELECT * FROM users WHERE username = ?", ("johndoe",))

    # index 0 is the user_id
    assert user[1] == "johndoe"
    assert user[2] != "this_is_my_password"
    assert user[3] == user_repo.roles["user"]


def test_register_duplicate_user(connector):
    user_repo = create_default_user(connector)

    response = user_repo.register(username="johndoe", password="another_pws", role="admin")
    assert response.ok is False
    assert response.result == "User already exists"


def test_authentication(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("johndoe", "this_is_my_password")

    assert response.ok is True
    assert response.result == 1


def test_authentication_wrong_pw(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("johndoe", "this_is_not_my_password")

    assert response.ok is False
    assert response.result == "Authentication failed"


def test_authentication_user_not_found(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("jane", "this_is_not_my_password")

    assert response.ok is False
    assert response.result == "User not found"


def test_authorization(connector):
    user_repo = create_default_user(connector, "admin")
    response = user_repo.authorization("johndoe", "admin")

    assert response.ok is True
    assert response.result is None


def test_not_authorized(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authorization("johndoe", "admin")

    assert response.ok is False
    assert response.result == "Not authorized"


def test_authorization_user_not_found(connector):
    user_repo = create_default_user(connector)

    response = user_repo.authorization("janedoe", "user")

    assert response.ok is False
    assert response.result == "User not found"


def test_get_username(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.get_username(user_id)
    assert response.ok is True
    assert response.result == "johndoe"


def test_get_role(connector):
    user_repo = create_default_user(connector, "admin")
    user_id = 1
    response = user_repo.get_role(user_id)

    assert response.ok is True
    assert response.result == enums.ROLES["admin"]


def test_save_password_to_user(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.save_password(user_id, "thehardestpassword", "mybank")
    assert response.ok is True
    assert response.result is None


def test_get_password(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.save_password(user_id, "thehardestpassword", "mybank")
    assert response.ok is True

    response = user_repo.get_password(user_id, "mybank")
    assert response.ok is True
    assert response.result == "thehardestpassword"


def test_get_password_not_found(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.save_password(user_id, "thehardestpassword", "mybank")
    assert response.ok is True

    response = user_repo.get_password(user_id, "not_mybank")
    assert response.ok is False
    assert response.result == "Password not found"


def test_get_all_passwords(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    user_repo.save_password(user_id, "thehardestpassword1", "mybank1")
    user_repo.save_password(user_id, "thehardestpassword2", "mybank2")
    user_repo.save_password(user_id, "thehardestpassword3", "mybank3")
    user_repo.save_password(user_id, "thehardestpassword4", "mybank4")
    user_repo.save_password(user_id, "thehardestpassword5", "mybank5")
    user_repo.save_password(user_id, "thehardestpassword6", "mybank6")
    user_repo.save_password(user_id, "thehardestpassword7", "mybank7")

    response = user_repo.get_all_passwords(user_id)
    assert response.ok is True
    assert response.result == [
        ("mybank1", "thehardestpassword1"),
        ("mybank2", "thehardestpassword2"),
        ("mybank3", "thehardestpassword3"),
        ("mybank4", "thehardestpassword4"),
        ("mybank5", "thehardestpassword5"),
        ("mybank6", "thehardestpassword6"),
        ("mybank7", "thehardestpassword7"),
    ]
