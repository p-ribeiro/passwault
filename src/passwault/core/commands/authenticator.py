from datetime import datetime

from src.passwault.core.utils.user_repository import UserRepository
from src.passwault.core.utils.logger import Logger
from src.passwault.core.utils.password import get_password_with_mask
from src.passwault.core.utils.session_manager import SessionManager


def register(username: str, password: str | None, role: str, user_repo: UserRepository) -> None:
    if password is None:
        password = get_password_with_mask()

    user_exists = user_repo.check_if_username_exists(username)
    if not user_exists.ok:
        Logger.error(user_exists.result)

    if user_exists.result is True:
        Logger.info("This username is already taken. Please provide another.")
        return

    response = user_repo.register(username, password, role)
    if not response.ok:
        Logger.error(response.result)
        return

    Logger.info("User created.")


def login(username: str, password: str, session_manager: SessionManager, user_repo: UserRepository) -> None:
    if password is None:
        password = get_password_with_mask()

    response = user_repo.authentication(username, password)
    if not response.ok:
        Logger.error(response.result)
        return
    role_response = user_repo.get_role()
    if not role_response.ok:
        Logger.error(role_response.result)
        return

    session_manager.user_repository = user_repo
    user_data = {"id": user_repo.id, "role": role_response.result, "time": datetime.now().isoformat()}
    session_manager.create_session(user_data)
    Logger.info("User logged in")


def logout(session_manager: SessionManager) -> None:
    session_manager.logout()
