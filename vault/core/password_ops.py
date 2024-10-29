from vault.core.utils.database import get_password, save_password


def save_pw(user_id: int, password: str, password_name: str):
    error = save_password(user_id, password, password_name)
    if error:
        print(error)
    print("Inserted with success")


def load_pw(user_id: int, password_name: str):
    pw = get_password(user_id, password_name)
    print(pw)
