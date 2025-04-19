from passwault.core.utils.user_repository import UserRepository
from passwault.core.utils.database import SQLiteConnector
from passwault.core.utils.session_manager import SessionManager


class AppContext:
    def __init__(self, connector: SQLiteConnector, session_manager: SessionManager):
        self.connector = connector
        self.session_manager = session_manager
        self.user_repo = UserRepository(connector)
        # self.logged_user = session_manager.get_logged_user()
