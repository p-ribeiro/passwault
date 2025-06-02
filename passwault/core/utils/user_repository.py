import bcrypt
from passwault.core.utils import enums
from passwault.core.utils.database import DatabaseConnector, IntegrityError
from passwault.core.utils.local_types import Fail, Response, Success


class UserRepository:
    def __init__(self, db_connector: DatabaseConnector):
        self.db = db_connector
        self.roles = enums.ROLES

    def check_if_username_exists(self, username: str) -> Response[bool]:
        query = "SELECT 1 FROM users WHERE username = {};"
        query = query.format(self.db.get_placeholder_symbol())
        result = self.db.fetch_one(query, (username,))
        return Success(result is not None)

    def register(self, username: str, password: str, role: str) -> Response[None]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""INSERT INTO users (username, password_hash, role)
                    VALUES ({placeholder}, {placeholder}, {placeholder});
                """

        if role.lower() not in self.roles:
            return Fail("This role is invalid")

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            self.db.execute_query(query, (username, password_hash, enums.ROLES[role.lower()]))
        except IntegrityError:
            return Fail("User already exists")
        except Exception as e:
            return Fail(f"Error during insertion: {str(e)}")

        return Success(None)

    def authentication(self, username: str, password: str) -> Response[int]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""SELECT user_id, password_hash
                    FROM users WHERE username=({placeholder});
                """

        try:
            user = self.db.fetch_one(query, (username,))

            if user is None:
                return Fail("User not found")

            user_id: str = int(user[0])
            password_hash: str = user[1]

            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                return Success(user_id)
            else:
                return Fail("Authentication failed")
        except Exception as e:
            return Fail(f"Error found while authenticating user: {e}")

    def authorization(self, username: str, required_role: str) -> Response[None]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""SELECT role
                    FROM users
                    WHERE username=({placeholder});
                """

        try:
            user = self.db.fetch_one(query, (username,))

            if user is None:
                return Fail("User not found")

            user_role = user[0]

            if enums.ROLES[required_role.lower()] == user_role:
                return Success(None)
            else:
                return Fail("Not authorized")
        except Exception as e:
            return Fail(f"Error authorizing user: {e}")

    def get_username(self, user_id: int) -> Response[str]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""
                SELECT username
                FROM users
                WHERE user_id=({placeholder});
                """

        try:
            username: str = self.db.fetch_one(query, (user_id,))

            if username:
                return Success(username[0])
            else:
                return Fail("User not found")

        except Exception as e:
            return Fail(f"Error getting user_id: {e}")

    def get_role(self, user_id: int) -> Response[int]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""
                SELECT role
                FROM users
                WHERE user_id=({placeholder});
                """

        try:
            user_role: int = self.db.fetch_one(query, (user_id,))

            if user_role:
                return Success(user_role[0])
            else:
                return Fail("User not found")

        except Exception as e:
            return Fail(f"Error getting user_role: {e}")

    def save_password(self, user_id: int, pw_username:str, password: str, password_name: str) -> Response[None]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""INSERT INTO passwords (password_name, password, username, user_id)
                    VALUES ({placeholder}, {placeholder}, {placeholder},{placeholder});
                """

        try:
            self.db.execute_query(query, (password_name, password, pw_username, user_id))
        except Exception as e:
            return Fail(f"Error while saving password: {e}")

        return Success(None)

    def get_password(self, user_id: int, password_name: str) -> Response[str]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""SELECT username, password_name, password
                    FROM passwords
                    WHERE password_name={placeholder}
                    AND user_id={placeholder};
                """

        try:
            password: list[str] = self.db.fetch_one(query, (password_name, user_id))

            if password:
                return Success(password)
            else:
                return Fail("Password not found")
        except Exception as e:
            return Fail(f"Error while retrieving password: {e}")

    def get_all_passwords(self, user_id: int) -> Response[list[str]]:
        placeholder = self.db.get_placeholder_symbol()
        query = f"""
                SELECT username, password_name, password
                FROM passwords
                WHERE user_id=({placeholder});
                """

        try:
            passwords: list[str] = self.db.fetch_all(query, (user_id,))
            if len(passwords) > 0:
                return Success(passwords)
            else:
                return Fail(f"There is not password for user: {user_id}")
        except Exception as e:
            return Fail(f"Error while retrieving all passwords: {e}")
