import json
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from functools import wraps
from os import path, remove
from pathlib import Path
from passwault.core.utils.logger import Logger


def check_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        # # lazy import of Embedder to avoid circular import
        # Embedder = importlib.import_module('passwault.imagepass.embedder').Embedder

        if not args:
            raise ValueError("No positon arguments provided, session is missing")

        # if isinstance(args[0], Embedder):
        #     session = kwargs["session_manager"]
        # else:
        #     session = args[-1]

        session = args[-1].session_manager

        if not isinstance(session, SessionManager):
            raise TypeError("Last object is not a session object")

        if not session.is_logged_in():
            Logger.info("User is not logged in")
            return

        func(*args, **kwargs)

    return wrapper


class SessionManager:
    def __init__(self, session_file=".session"):
        self.root_path = Path(__file__).resolve().parents[4]
        self.session_file_path = self.root_path / session_file
        self.key_file_path = self.root_path / ".enckey"
        self.session = self._load_session()

    def _create_secret_key(self):
        if not path.isfile(self.key_file_path):
            key = Fernet.generate_key()
            with open(self.key_file_path, "wb") as f:
                f.write(key)

    def _get_secret_key(self):
        with open(self.key_file_path) as f:
            return f.read()

    def _load_session(self):

        if path.exists(self.session_file_path):

            if not path.isfile(self.key_file_path):
                raise Exception("Error loading sesssion. There is no secret key")

            # retrieves encryption key
            secret_key = self._get_secret_key()
            fernet = Fernet(secret_key)

            with open(self.session_file_path, "rb") as sf:
                encrypted_session = sf.read()

            decrypted_data = fernet.decrypt(encrypted_session)

            return json.loads(decrypted_data.decode())

        return None

    def _save_session(self):

        # creates an encryption key if not exists then retrieve it
        self._create_secret_key()
        secret_key = self._get_secret_key()
        fernet = Fernet(secret_key)

        # encrypt session
        encrypted_session = fernet.encrypt(json.dumps(self.session).encode())

        with open(self.session_file_path, "wb") as sf:
            sf.write(encrypted_session)

    def is_logged_in(self):
        return self.session is not None

    def create_session(self, user_data):
        self.session = user_data
        self._save_session()

    def logout(self):
        self.session = None
        self._save_session()
        remove(self.session_file_path)

    def get_session(self):
        return self.session

    def expire_session(self):
        if path.exists(self.session_file_path):
            session = self._load_session()
            if session:
                time_difference = datetime.now() - datetime.fromisoformat(
                    session["time"]
                )
                if time_difference >= timedelta(minutes=10):
                    self.logout()
