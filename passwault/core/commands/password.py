from random import choice

from passwault.core.utils.database import get_password, save_password
from passwault.core.utils.logger import Logger


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


def generate_pw(has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True):
    SYMBOLS_RANGE = [33, 38]
    DIGITS_RANGE = [48, 57]
    UPPERCASE_RANGE = [65, 90]
    LOWERCASE_RANGE = [97, 122]

    pool = [i for i in range(LOWERCASE_RANGE[0], LOWERCASE_RANGE[1] + 1)]

    if has_symbols:
        pool.extend([i for i in range(SYMBOLS_RANGE[0], SYMBOLS_RANGE[1] + 1)])

    if has_digits:
        pool.extend([i for i in range(DIGITS_RANGE[0], DIGITS_RANGE[1] + 1)])

    if has_uppercase:
        pool.extend([i for i in range(UPPERCASE_RANGE[0], UPPERCASE_RANGE[1] + 1)])

    password = "".join([chr(choice(pool)) for _ in range(len)])

    return password
