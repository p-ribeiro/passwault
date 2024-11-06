from typing import Callable

from passwault.core.utils.database import add_user, authentication, get_role
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


def register(username: str, password: str, role: str) -> None:

    error = add_user(username, password, role)
    if error:
        Logger.error(error)


def login(username: str, password: str, session_manager: SessionManager) -> None:
    if session_manager.is_logged_in():
        Logger.info("User already logged in")
    response = authentication(username, password)
    if isinstance(response, str):
        Logger.error(response)
        return
    else:
        user_data = {"username": username, "role": get_role(username)}
        session_manager.create_session(user_data)
        Logger.info("User logged in")
