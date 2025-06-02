from passwault.core.utils import enums
from passwault.core.utils.database import SQLiteConnector
from passwault.core.utils.user_repository import UserRepository
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
    response = user_repo.save_password(user_id, "email@email.com", "thehardestpassword", "mybank")
    assert response.ok is True
    assert response.result is None


def test_get_password(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.save_password(user_id, "email@email.com","thehardestpassword", "mybank")
    assert response.ok is True

    response = user_repo.get_password(user_id, "mybank")
    assert response.ok is True
    assert response.result == ("email@email.com", "mybank", "thehardestpassword")


def test_get_password_not_found(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    response = user_repo.save_password(user_id, "email@email.com","thehardestpassword", "mybank")
    assert response.ok is True

    response = user_repo.get_password(user_id, "not_mybank")
    assert response.ok is False
    assert response.result == "Password not found"


def test_get_all_passwords(connector):
    user_repo = create_default_user(connector)
    user_id = 1
    user_repo.save_password(user_id, "email1@email.com", "thehardestpassword1", "mybank1")
    user_repo.save_password(user_id, "email2@email.com", "thehardestpassword2", "mybank2")
    user_repo.save_password(user_id, "email3@email.com", "thehardestpassword3", "mybank3")
    user_repo.save_password(user_id, "email4@email.com", "thehardestpassword4", "mybank4")
    user_repo.save_password(user_id, "email5@email.com", "thehardestpassword5", "mybank5")
    user_repo.save_password(user_id, "email6@email.com", "thehardestpassword6", "mybank6")
    user_repo.save_password(user_id, "email7@email.com", "thehardestpassword7", "mybank7")

    response = user_repo.get_all_passwords(user_id)
    assert response.ok is True
    assert response.result == [
        ("email1@email.com", "mybank1", "thehardestpassword1"),
        ("email2@email.com", "mybank2", "thehardestpassword2"),
        ("email3@email.com", "mybank3", "thehardestpassword3"),
        ("email4@email.com", "mybank4", "thehardestpassword4"),
        ("email5@email.com", "mybank5", "thehardestpassword5"),
        ("email6@email.com", "mybank6", "thehardestpassword6"),
        ("email7@email.com", "mybank7", "thehardestpassword7"),
    ]
