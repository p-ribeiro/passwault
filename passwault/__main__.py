from passwault.core.utils.app_context import AppContext
from passwault.core.utils.session_manager import SessionManager
from passwault.core.utils.database import SQLiteConnector
from passwault.core.cli import cli


def main():
    # Expire previous session
    session_manager = SessionManager()
    session_manager.expire_session()

    # Initialize database
    db = SQLiteConnector("passwault.db")
    db.init_db()

    try:
        ctx = AppContext(db, session_manager)
        cli(ctx)
    finally:
        db.close()


if __name__ == "__main__":
    main()
