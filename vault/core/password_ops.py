from vault.core.utils.database import get_password, save_password
from vault.core.utils.logger import Logger


def save_pw(user_id: int, password: str, password_name: str):
    error = save_password(user_id, password, password_name)
    if error:
        Logger.error(error)
        return

    Logger.info("Inserted with success")


def load_pw(user_id: int, password_name: str):
    pw = get_password(user_id, password_name)
    if pw.startswith("Error"):
        Logger.error(pw)
        return

    print(f"Password for {password_name}: {pw}")
