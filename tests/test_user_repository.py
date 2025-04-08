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

def create_default_user(connector, role = "user"):
    user_repo = UserRepository(connector)
    response = user_repo.add_user(
        username = "johndoe",
        password = "this_is_my_password",
        role = role
        )
    assert response.ok == True
    
    return user_repo
    
def test_check_if_username_exists(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))
    user_repo = UserRepository(connector)
    response = user_repo.check_if_username_exists("johndoe")
    
    assert response.ok == True
    assert response.result == True

def test_check_if_username_not_exists(connector):
    connector.execute_query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("johndoe", "mypw", enums.ROLES["admin"]))
    user_repo = UserRepository(connector)
    response = user_repo.check_if_username_exists("jane")
    
    assert response.ok == True    
    assert response.result == False

def test_add_user(connector):
    user_repo = create_default_user(connector)
    user = connector.fetch_one("SELECT * FROM users WHERE username = ?", ("johndoe",))

    # index 0 is the user_id
    assert user[1] == "johndoe"
    assert user[2] != "this_is_my_password"
    assert user[3] == user_repo.roles["user"]

def test_add_duplicate_user(connector):
    user_repo = create_default_user(connector)
    
    response = user_repo.add_user(
        username = "johndoe",
        password = "another_pws",
        role = "admin"
        )
    assert response.ok == False
    assert response.result == "User already exists"

def test_authentication(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("johndoe", "this_is_my_password")
    
    assert response.ok == True
    assert response.result == 1

def test_authentication_wrong_pw(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("johndoe", "this_is_not_my_password")
    
    assert response.ok == False
    assert response.result == "Authentication failed"
 
def test_authentication_user_not_found(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authentication("jane", "this_is_not_my_password")
    
    assert response.ok == False
    assert response.result == "User not found" 

def test_authorization(connector):
    user_repo = create_default_user(connector, "admin")
    response = user_repo.authorization("johndoe", "admin")
    
    assert response.ok == True
    assert response.result == None

def test_not_authorized(connector):
    user_repo = create_default_user(connector)
    response = user_repo.authorization("johndoe", "admin")
    
    assert response.ok == False
    assert response.result == "Not authorized"

def test_authorization_user_not_found(connector):
    user_repo = create_default_user(connector)
    
    response = user_repo.authorization("janedoe", "user")

    assert response.ok == False
    assert response.result == "User not found"

def test_get_user_id(connector):
    user_repo = create_default_user(connector)
    user_repo.add_user("janedoe", "testing", "user")
    user_repo.add_user("bobthebuilder", "hammertime", "admin")
    
    response = user_repo.get_user_id("bobthebuilder")
    
    assert response.ok == True
    assert response.result == 3

def test_get_user_not_found(connector):
    user_repo = create_default_user(connector)
    user_repo.add_user("janedoe", "testing", "user")
    user_repo.add_user("bobthebuilder", "hammertime", "admin")
    
    response = user_repo.get_user_id("jacktheripper")
    
    assert response.ok == False
    assert response.result == "User not found"

def test_get_role(connector):
    user_repo = create_default_user(connector, "admin")
    
    response = user_repo.get_role("johndoe")
    
    assert response.ok == True
    assert response.result == enums.ROLES["admin"]
    
def test_get_role_user_not_found(connector):
    user_repo = create_default_user(connector, "admin")
    
    response = user_repo.get_role("janedoe")
    
    assert response.ok == False
    assert response.result == "User not found"

def test_save_password_to_user(connector):
    user_repo = create_default_user(connector)
    
    response = user_repo.save_password(1, "thehardestpassword", "mybank")
    assert response.ok == True
    assert response.result == None

def test_save_password_to_non_existing_user(connector):
    user_repo = create_default_user(connector)
    
    response = user_repo.save_password(2, "thehardestpassword", "mybank")
    
    assert response.ok == False
    assert "Error while saving password" in response.result 

def test_get_password(connector):
    user_repo = create_default_user(connector)
    
    response = user_repo.save_password(1, "thehardestpassword", "mybank")
    assert response.ok == True

    response = user_repo.get_password(1, "mybank")    
    assert response.ok == True
    assert response.result == "thehardestpassword"
    



    
    
    
    