from vault.core.utils import database


def register(username: str, password: str, role: str) -> None:
    error = database.add_user(username, password, role)
    if error:
        print(error)


def login(username: str, password: str) -> None:
    from vault.core.cli import logged_in

    response = database.authenticate(username, password)
    if isinstance(response, str):
        print(response)
        return

    logged_in(response)


if __name__ == "__main__":
    database.init_db()
