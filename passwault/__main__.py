# from passwault.core.utils.session_manager import SessionManager
from passwault.core.database.models import Base, engine
from passwault.core.database.password_manager import save_password, get_password_by_username
from passwault.core.cli import cli


def main():
    # Expire previous session
    # session_manager = SessionManager()
    # session_manager.expire_session()

    # create the tables
    Base.metadata.create_all(engine)

    

    # initalize the system
    # cli()


if __name__ == "__main__":
    main()
