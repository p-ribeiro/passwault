from datetime import datetime
from enum import Enum


class Colors(Enum):
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"


class Logger:
    @staticmethod
    def _current_timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def info(message: str) -> None:
        print(f'{Colors.GREEN.value}[INFO] {Logger._current_timestamp()} - {message}{Colors.RESET.value}')

    def error(message: str) -> None:
        print(f'{Colors.RED.value}[ERROR] {Logger._current_timestamp()} - {message}{Colors.RESET.value}')

    def debug(message: str) -> None:
        print(f'{Colors.YELLOW.value}[DEBUG] {Logger._current_timestamp()} - {message}{Colors.RESET.value}')
