import re
from pathlib import Path
from random import choice

from passwault.core.utils.database import get_password, save_password
from passwault.core.utils.file_handler import read_file, valid_file
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


def save_pw(password: str, password_name: str, file: str, session_manager: SessionManager):
    if not session_manager.is_logged_in():
        Logger.info("User is not logged in")
        return

    session = session_manager.get_session()
    user_id = session["id"]

    if file:
        pw_pairs = read_file(file)
        if pw_pairs is None:
            Logger.error("TBD error invalid file")
            return
        
        for pw_name, pw in pw_pairs:
            save_password(user_id, pw, pw_name)
        
        Logger.info("Successfully imported the password file")
        return
        
        
    if (password_name and password is None) or (password and password_name is None):
        Logger.error("You should insert a password with a password_name")
        return
    
    response = save_password(user_id, password, password_name)
    if not response.ok:
        Logger.error(response.result)
        return

    Logger.info("Password inserted with success")


def load_pw(password_name: str, session_manager: SessionManager):

    if not session_manager.is_logged_in():
        Logger.info("User is not logged in")
        return

    session = session_manager.get_session()
    user_id = session["id"]

    response = get_password(user_id, password_name)
    if not response.ok:
        Logger.error(response.result)
        return

    print(f"Password for {password_name}: {response.result}")


def generate_pw(
    password_length: int, has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True
) -> None:

    MAX_ITER = 10
    SYMBOLS_RANGE = [33, 38]
    DIGITS_RANGE = [48, 57]
    UPPERCASE_RANGE = [65, 90]
    LOWERCASE_RANGE = [97, 122]

    # validates the password
    def _validate(password: str) -> bool:
        if has_symbols:
            if not bool(re.search(r"[^a-zA-Z0-9\s]", password)):
                return False
        if has_digits:
            if not any(char.isdigit() for char in password):
                return False
        if has_uppercase:
            if not any(char.isupper() for char in password):
                return False

        return True

    count = 0
    while True:
        pool = [i for i in range(LOWERCASE_RANGE[0], LOWERCASE_RANGE[1] + 1)]

        if has_symbols:
            pool.extend([i for i in range(SYMBOLS_RANGE[0], SYMBOLS_RANGE[1] + 1)])

        if has_digits:
            pool.extend([i for i in range(DIGITS_RANGE[0], DIGITS_RANGE[1] + 1)])

        if has_uppercase:
            pool.extend([i for i in range(UPPERCASE_RANGE[0], UPPERCASE_RANGE[1] + 1)])

        password = "".join([chr(choice(pool)) for _ in range(password_length)])

        if _validate(password):
            break

        # failsafe for infinite loop
        count += 1
        if count >= MAX_ITER:
            Logger.error("Error generating password")
            return

    print(f"The generated password is: {password}")
