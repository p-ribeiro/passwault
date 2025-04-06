from logging import PlaceHolder
import sqlite3
from typing import List
import bcrypt
from passwault.core.utils.database import DatabaseConnector, IntegrityError
from passwault.core.utils.local_types import Response

ROLES = {"admin": 1, "user": 2}

class UserRepository:
    def __init__(self, db_connector: DatabaseConnector):
        self.db = db_connector
        self.db.connect()
        self.roles = ROLES
    
    def check_if_username_exists(self, username: str) -> Response:
        query = "SELECT 1 FROM users WHERE username = {} LIMIT 1;"
        query = query.format(self.db.get_placeholder_symbol())
        result = self.fetch_one(query, (username,))
        return Response(True, result is not None)
            

    def add_user(self, username: str, password: str, role: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"INSERT INTO users (username, password_hash, role) VALUES ({placeholder}, {placeholder}, {placeholder});"

        if role.lower() not in self.roles:
            return Response(False, "This role is invalid")

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            self.db.execute_query(query, (username, password_hash, ROLES[role.lower()]))
        except IntegrityError as ie:
            return Response(False, f"User already exists")
        except Exception as e:
            return Response(False, f"Error during insertion: {str(e)}")
        finally:
            self.db.close()

        return Response(True, None)


    def authentication(self, username: str, password: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT user_id, password_hash FROM users WHERE username=({placeholder});"

        try:
            user = self.db.fetch_one(query, (username, ))

            if user is None:
                return Response(False, "User not found")

            user_id: int = user[0]
            password_hash: str = user[1]

            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                return Response(True, user_id)
            else:
                return Response(False, "Authentication failed")
        except Exception as e:
            return Response(False, f"Error found while authenticating user: {e}")
        finally:
            self.db.close()


    def authorization(self, username: str, required_role: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT role FROM users WHERE username=({placeholder});"

        try:
            user = self.db.fetchone(query, (username,))

            if user is None:
                return (False, "User not found")

            user_role = user[0]

            if required_role.lower() == user_role:
                return Response(True, None)
            else:
                return Response(False, "Not authorized")
        except Exception as e:
            return Response(False, f"Error authorizing user: {e}")
        finally:
            self.db.close()


    def get_user_id(self, username: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT user_id FROM users WHERE username=({placeholder});"
        
        try:
            user_id: int = self.db.fetchone(query, username)

            if user_id:
                return Response(True, user_id[0])
            else:
                return Response(False, "User not found")

        except Exception as e:
            return Response(False, f"Error getting user_id: {e}")
        finally:
            self.db.close()


    def get_role(self, username: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT role FROM users WHERE username=({placeholder});" 

        try:
            user_role: int = self.db.fetchone(query, (username,))

            if user_role:
                return Response(True, user_role[0])
            else:
                return Response(False, "User not found")

        except Exception as e:
            return Response(False, f"Error getting user_role: {e}")
        finally:
            self.db.close()


    def save_password(self, user_id: int, password: str, password_name: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"INSERT INTO passwords (password_name, password, user_id) VALUES ({placeholder}, {placeholder}, {placeholder});"

        try:
            self.db.execute_query(query, (password_name, password, user_id))
        except Exception as e:
            return Response(False, f"Error while saving password: {e}")
        finally:
            self.db.close()
        return Response(True, None)


    def get_password(self, user_id: str, password_name: str) -> Response:
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT password FROM passwords WHERE password_name={placeholder} AND user_id={placeholder};"

        try:
            password: str = self.db.fetchone(query, (user_id, password_name))

            if password:
                return Response(True, password[0])
            else:
                return Response(False, "Password not found")
        except Exception as e:
            return Response(False, f"Error while retrieving password: {e}")
        finally:
            self.db.close()


    def get_all_passwords(self, user_id: str):
        placeholder = self.db.get_placeholder_symbol()
        query = f"SELECT password_name, password FROM passwords WHERE user_id=({placeholder});"

        try:
            passwords: List[str] = self.db.fetchall(query, (user_id,))
            if len(passwords) > 0:
                return Response(True, passwords)
            else:
                return Response(True, f"There is not password for user: {user_id}")
        except Exception as e:
            return Response(False, f"Error while retrieving all passwords: {e}")
        finally:
            self.db.close()
