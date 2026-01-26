"""Custom exceptions for Passwault.

This module defines custom exception classes used throughout the application.
"""


class PasswaultError(Exception):
    """Base exception for all Passwault errors."""
    pass


class AuthenticationError(PasswaultError):
    """Raised when authentication fails."""
    pass


class DatabaseError(PasswaultError):
    """Raised when database operations fail."""
    pass


class EncryptionError(PasswaultError):
    """Raised when encryption/decryption operations fail."""
    pass


class ResourceNotFoundError(PasswaultError):
    """Raised when a requested resource is not found."""
    pass


class ResourceExistsError(PasswaultError):
    """Raised when trying to create a resource that already exists."""
    pass


class ClipboardError(PasswaultError):
    """Raised when clipboard operations fail."""
    pass
