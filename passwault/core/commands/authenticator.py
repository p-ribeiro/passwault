from datetime import datetime

from passwault.core.utils.app_context import AppContext
from passwault.core.utils.logger import Logger
from passwault.core.utils.password import get_password_with_mask


def register(username: str, password: str | None, role: str, ctx: AppContext) -> None:
    if password is None:
        password = get_password_with_mask()

    user_exists = ctx.user_repo.check_if_username_exists(username)
    if not user_exists.ok:
        Logger.error(user_exists.result)

    if user_exists.result is True:
        Logger.info("This username is already taken. Please provide another.")
        return

    response = ctx.user_repo.register(username, password, role)
    if not response.ok:
        Logger.error(response.result)
        return
    Logger.info("User created.")


def login(username: str, password: str, ctx: AppContext) -> None:
    if password is None:
        password = get_password_with_mask()

    response = ctx.user_repo.authentication(username, password)
    if not response.ok:
        Logger.error(response.result)
        return
    user_id = response.result
    role_response = ctx.user_repo.get_role(user_id)
    if not role_response.ok:
        Logger.error(role_response.result)
        return

    user_data = {"id": user_id, "role": role_response.result, "time": datetime.now().isoformat()}
    ctx.session_manager.create_session(user_data)
    Logger.info("User logged in")


def logout(ctx: AppContext) -> None:
    ctx.session_manager.logout()
