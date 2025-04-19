from abc import ABC, abstractmethod
import sqlite3
from typing import Any, Generic, Optional, TypeVar, Union


class DatabaseError(Exception):
    pass


class IntegrityError(DatabaseError):
    pass


class ConnectionError(DatabaseError):
    pass


T = TypeVar('T')


class DatabaseConnector(ABC, Generic[T]):

    connection: Any
    cursor: T

    def __init__(self) -> None:
        self.connection = None
        self.cursor = None

    @abstractmethod
    def connect(self):
        pass

    @abstractmethod
    def _map_exception(self, exception):
        pass

    def execute_query(self, query: str, params: Optional[tuple] = None) -> T:
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            self.connection.commit()

            return self.cursor
        except Exception as e:
            # Map the exception to our custom hierarchy
            mapped_exception = self._map_exception(e)
            if mapped_exception:
                raise mapped_exception
            # If no mapping exists, re-raise the original exception
            raise

    # @abstractmethod
    # def insert_one(self):
    #     pass

    @abstractmethod
    def fetch_all(self, query: str, params: Optional[tuple] = None) -> list[Any]:
        pass

    @abstractmethod
    def fetch_one(self, query: str, params: Optional[tuple] = None) -> Any:
        pass

    @abstractmethod
    def get_placeholder_symbol(self):
        pass

    def close(self):
        if self.connection:
            self.connection.close()


SQLiteCursor = TypeVar('SQLiteCursor', bound='sqlite3.Cursor')


class SQLiteConnector(DatabaseConnector[SQLiteCursor]):

    def __init__(self, db_path: str) -> None:
        super().__init__()
        self.db_path = db_path

    def _map_exception(self, exception) -> Union[IntegrityError, ConnectionError]:
        if isinstance(exception, sqlite3.IntegrityError):
            if "UNIQUE constraint failed" in str(exception):
                return IntegrityError(f"Record already exists: {str(exception)}")

        return None

    def connect(self) -> 'SQLiteConnector':
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.connection.cursor()
        return self

    def init_db(self) -> None:
        self.connect()

        query_create_users = """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role INT NOT NULL
            );
            """
        query_create_passwords = """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_name TEXT NOT NULL,
                password TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            """

        self.cursor.execute(query_create_users)
        self.cursor.execute(query_create_passwords)

        self.connection.commit()

    def fetch_one(self, query: str, params: Optional[tuple] = None) -> Any:
        self.execute_query(query, params)
        return self.cursor.fetchone()

    def fetch_all(self, query: str, params: Optional[tuple] = None) -> list[Any]:
        self.execute_query(query, params)
        return self.cursor.fetchall()

    def get_placeholder_symbol(self):
        return "?"
