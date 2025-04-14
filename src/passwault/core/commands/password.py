import re
from random import choice

from src.passwault.core.utils.app_context import AppContext
from src.passwault.core.utils.file_handler import read_file
from src.passwault.core.utils.logger import Logger
from src.passwault.core.utils.session_manager import check_session


@check_session
def save_pw(password: str, password_name: str, file: str, ctx: AppContext):

    session = ctx.session_manager.get_session()
    user_id = session["id"]

    if file:
        pw_pairs = read_file(file)
        if pw_pairs is None:
            Logger.error("TBD error invalid file")
            return

        for pw_name, pw in pw_pairs:
            ctx.user_repo.save_password(user_id, pw, pw_name)

        Logger.info("Successfully imported the password file")
        return

    if (password_name and password is None) or (password and password_name is None):
        Logger.error("You should insert a password with a password_name")
        return

    response = ctx.user_repo.save_password(user_id, password, password_name)
    if not response.ok:
        Logger.error(response.result)
        return

    Logger.info("Password inserted with success")


@check_session
def load_pw(password_name: str, all_passwords: bool, ctx: AppContext):

    session = ctx.session_manager.get_session()
    user_id = session["id"]

    # return all passwords and return
    if all_passwords is True:
        response = ctx.user_repo.get_all_passwords(user_id)
        if not response.ok:
            Logger.error(response.result)
            return
        for pws in response.result:
            print(f"{pws[0]}: {pws[1]}")
        return

    # returns password
    response = ctx.user_repo.get_password(user_id, password_name)
    if not response.ok:
        Logger.error(response.result)
        return

    print(f"Password for {password_name}: {response.result}")


def generate_pw(password_length: int, has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True) -> None:

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
