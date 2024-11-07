import json
from datetime import datetime, timedelta
from os import path
from pathlib import Path


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


if __name__ == "__main__":
    sm = SessionManager()
    print(sm.root_path)
