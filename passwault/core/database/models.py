from datetime import datetime

from sqlalchemy import (
    Column,
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
from sqlalchemy.orm import relationship, declarative_base, sessionmaker
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    """User model for authentication and encryption key management.

    Each user has a unique username and master password. The master password
    is hashed with bcrypt for authentication, and a separate salt is used
    for deriving the encryption key via PBKDF2.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    master_password_hash = Column(LargeBinary, nullable=False)
    salt = Column(LargeBinary, nullable=False)
    kdf_algorithm = Column(String(50), default="PBKDF2", nullable=False)
    kdf_iterations = Column(Integer, default=600000, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_login = Column(DateTime, nullable=True)

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

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    resource_name = Column(String(100), nullable=False)
    username = Column(String(255), nullable=True)
    encrypted_password = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    website = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(String(255), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
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
engine = create_engine("sqlite:///passwault.db", echo=True)
SessionLocal = sessionmaker(bind=engine)