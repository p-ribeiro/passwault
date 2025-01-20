from argparse import ArgumentError
from datetime import datetime

from passwault.core.utils.database import (add_user, authentication, check_if_username_exists, get_role,
                                           get_user_id)
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask
from passwault.core.utils.session_manager import SessionManager


def register(username: str, password: str, role: str) -> None:
    if password is None:
        password = get_password_with_mask()
    
    user_exists = check_if_username_exists(username)
    if not user_exists.ok:
        Logger.error(user_exists.result)
    
    if user_exists.result is not None:
        Logger.info("This username is already taken. Please provide another.")
        return
    
    response = add_user(username, password, role)
    if not response.ok:
        Logger.error(response.result)
        return

    Logger.info("User created.")


def login(username: str, password: str, session_manager: SessionManager) -> None:
    
    if password is None:
        password = get_password_with_mask()
    
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
