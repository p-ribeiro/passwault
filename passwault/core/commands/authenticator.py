from datetime import datetime

from passwault.core.utils.database import (add_user, authentication, get_role,
                                           get_user_id)
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager


def register(username: str, password: str, role: str) -> None:

    response = add_user(username, password, role)
    if not response.ok:
        Logger.error(response.result)
        return

    Logger.info("User created.")


def login(username: str, password: str, session_manager: SessionManager) -> None:
    response = authentication(username, password)
    if not response.ok:
        Logger.error(response.result)
        return

    user_id_response = get_user_id(username)
    if not user_id_response.ok:
        Logger.error(user_id_response.result)
        return

    role_response = get_role(username)
    if not role_response.ok:
        Logger.error(role_response.result)
        return

    user_data = {"id": user_id_response.result, "role": role_response.result, "time": datetime.now().isoformat()}
    session_manager.create_session(user_data)
    Logger.info("User logged in")


def logout(session_manager: SessionManager) -> None:
    session_manager.logout()
