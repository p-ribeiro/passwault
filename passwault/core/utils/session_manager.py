import json
from datetime import datetime, timedelta
from functools import wraps
from multiprocessing import Value
from os import path
from pathlib import Path

from passwault.core.utils.logger import Logger


def check_session(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        if not args:
            raise ValueError("No positon arguments provided, session is missing")

        session = args[-1]

        if not isinstance(session, SessionManager):
            raise TypeError("Last object is not a session object")

        if not session.is_logged_in():
            Logger.info("User is not logged in")
            return

        func(*args, **kwargs)

    return decorator


class SessionManager:
    def __init__(self, session_file=".session"):
        self.root_path = Path(__file__).resolve().parents[3]
        self.session_file_path = self.root_path / session_file
        self.session = self._load_session()

    def _load_session(self):
        if path.exists(self.session_file_path):
            with open(self.session_file_path, "r") as sf:
                return json.load(sf)
        return None

    def _save_session(self):
        with open(self.session_file_path, "w") as sf:
            json.dump(self.session, sf)

    def is_logged_in(self):
        return self.session is not None

    def create_session(self, user_data):
        self.session = user_data
        self._save_session()

    def logout(self):
        self.session = None
        self._save_session()

    def get_session(self):
        return self.session

    def expire_session(self):
        if path.exists(self.session_file_path):
            with open(self.session_file_path, "r") as sf:
                session = json.load(sf)
            if session:
                time_difference = datetime.now() - datetime.fromisoformat(session["time"])
                if time_difference >= timedelta(minutes=10):
                    self.logout()
