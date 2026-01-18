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
)
from sqlalchemy.orm import (
    relationship,
    declarative_base,
    sessionmaker,
    Mapped,
    mapped_column,
)
from sqlalchemy.sql import func

from passwault.core.utils.data_dir import get_data_dir

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
    encrypted_password: Mapped[str] = mapped_column(LargeBinary, nullable=False)
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


# Database Setup
DB_PATH = get_data_dir() / "passwault.db"
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
SessionLocal = sessionmaker(bind=engine)
