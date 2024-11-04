from typing import Callable

from vault.core.utils.database import add_user, authenticate
from vault.core.utils.logger import Logger


def register(username: str, password: str, role: str) -> None:
    error = add_user(username, password, role)
    if error:
        Logger.error(error)


def login(username: str, password: str, callback: Callable[[int], None]) -> None:
    response = authenticate(username, password)
    if isinstance(response, str):
        Logger.error(response)
        return

    callback(response)
