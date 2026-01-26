import datetime as dt

from sqlalchemy import (
    Integer,
    String,
    Text,
    ForeignKey,
    LargeBinary,
    DateTime,
    Index,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import (
    relationship,
    declarative_base,
    sessionmaker,
    Mapped,
    mapped_column,
)
from sqlalchemy.pool import QueuePool, NullPool
from sqlalchemy.sql import func

from passwault.core.config import Config, DatabaseType

Base = declarative_base()


class User(Base):
    """User model for authentication and encryption key management.

    Each user has a unique username and master password. The master password
    is hashed with bcrypt for authentication, and a separate salt is used
    for deriving the encryption key via PBKDF2.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=True)
    master_password_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kdf_algorithm: Mapped[str] = mapped_column(
        String(50), default="PBKDF2", nullable=False
    )
    kdf_iterations: Mapped[int] = mapped_column(Integer, default=600000, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    last_login: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship to passwords
    passwords = relationship(
        "PasswordManager", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


class PasswordManager(Base):
    """Password manager model for storing encrypted passwords.

    Each password entry belongs to a user and contains the encrypted
    password along with the nonce needed for AES-GCM decryption.
    """

    __tablename__ = "password_manager"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    resource_name: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=True)
    encrypted_password: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    website: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    tags: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationship to user
    user = relationship("User", back_populates="passwords")

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint("user_id", "resource_name", name="uix_user_resource"),
        Index("idx_user_passwords", "user_id"),
        Index("idx_resource_name", "user_id", "resource_name"),
    )

    def __repr__(self):
        return (
            f"<PasswordManager(id={self.id}, user_id={self.user_id}, "
            f"resource_name='{self.resource_name}')>"
        )


def _get_engine_options(database_type: DatabaseType) -> dict:
    """Get engine options based on database type.

    Args:
        database_type: The target database type

    Returns:
        Dictionary of engine options
    """
    if database_type == DatabaseType.SQLITE:
        return {
            "echo": False,
            "poolclass": NullPool,  # SQLite doesn't support connection pooling well
        }
    else:  # PostgreSQL
        return {
            "echo": False,
            "poolclass": QueuePool,
            "pool_size": 5,
            "max_overflow": 10,
            "pool_pre_ping": True,  # Verify connections are alive
        }


def create_db_engine():
    """Create database engine based on configuration.

    Returns:
        SQLAlchemy Engine instance
    """
    database_url = Config.get_database_url()
    database_type = Config.get_database_type()
    options = _get_engine_options(database_type)

    db_engine = create_engine(database_url, **options)

    # SQLite-specific: Enable foreign key constraints
    if database_type == DatabaseType.SQLITE:

        @event.listens_for(db_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return db_engine


def get_session_factory(db_engine=None):
    """Get session factory for the given engine.

    Args:
        db_engine: SQLAlchemy engine (creates new if None)

    Returns:
        sessionmaker instance
    """
    if db_engine is None:
        db_engine = create_db_engine()
    return sessionmaker(bind=db_engine)


# Module-level instances for backward compatibility
engine = create_db_engine()
SessionLocal = get_session_factory(engine)
