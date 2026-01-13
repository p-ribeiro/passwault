"""Cryptography service for password encryption and key management.

This module provides all cryptographic operations needed for secure
password storage and user authentication, including:
- Master password hashing (bcrypt)
- Encryption key derivation (PBKDF2-HMAC-SHA256)
- Password encryption/decryption (AES-256-GCM)
"""

import os
from typing import Tuple

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoService:
    """Service class for cryptographic operations.

    Provides methods for:
    - Generating cryptographically secure random salts
    - Hashing and verifying master passwords with bcrypt
    - Deriving encryption keys from master passwords using PBKDF2
    - Encrypting and decrypting passwords using AES-256-GCM

    Security Notes:
    - Uses bcrypt with automatic cost factor (currently 12)
    - Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
    - Uses AES-256-GCM for authenticated encryption
    - Uses os.urandom() for cryptographically secure randomness
    """

    # Default KDF parameters (can be overridden for future-proofing)
    DEFAULT_KDF_ITERATIONS = 600000
    DEFAULT_SALT_LENGTH = 32
    DEFAULT_NONCE_LENGTH = 12  # 96 bits for GCM

    @staticmethod
    def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
        """Generate a cryptographically secure random salt.

        Args:
            length: Length of the salt in bytes (default: 32 bytes)

        Returns:
            Random bytes suitable for use as a cryptographic salt
        """
        return os.urandom(length)

    @staticmethod
    def hash_master_password(password: str) -> bytes:
        """Hash a master password using bcrypt.

        Uses bcrypt with automatic salt generation and cost factor.
        The resulting hash includes the salt and cost parameters,
        allowing for future verification.

        Args:
            password: The plaintext master password to hash

        Returns:
            bcrypt hash as bytes (includes salt and parameters)
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    @staticmethod
    def verify_master_password(password: str, password_hash: bytes) -> bool:
        """Verify a master password against a bcrypt hash.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            password: The plaintext password to verify
            password_hash: The bcrypt hash to verify against

        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def derive_encryption_key(
        master_password: str,
        salt: bytes,
        iterations: int = DEFAULT_KDF_ITERATIONS
    ) -> bytes:
        """Derive an encryption key from a master password using PBKDF2.

        Uses PBKDF2-HMAC-SHA256 with configurable iterations (default: 600,000).
        The derived key is suitable for use with AES-256 encryption.

        Args:
            master_password: The master password to derive from
            salt: User-specific salt (should be stored with user record)
            iterations: Number of PBKDF2 iterations (default: 600,000)

        Returns:
            32-byte (256-bit) encryption key suitable for AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(master_password.encode('utf-8'))

    @staticmethod
    def encrypt_password(plaintext: str, encryption_key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt a password using AES-256-GCM.

        AES-GCM provides authenticated encryption, ensuring both
        confidentiality and integrity of the encrypted data.

        Args:
            plaintext: The plaintext password to encrypt
            encryption_key: 32-byte encryption key (from derive_encryption_key)

        Returns:
            Tuple of (ciphertext, nonce) where:
            - ciphertext: Encrypted password as bytes
            - nonce: 12-byte nonce used for this encryption (must be stored)

        Raises:
            ValueError: If encryption_key is not 32 bytes
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes (256 bits)")

        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(CryptoService.DEFAULT_NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        return ciphertext, nonce

    @staticmethod
    def decrypt_password(
        ciphertext: bytes,
        nonce: bytes,
        encryption_key: bytes
    ) -> str:
        """Decrypt a password using AES-256-GCM.

        Verifies the authentication tag to ensure data integrity.

        Args:
            ciphertext: The encrypted password bytes
            nonce: The 12-byte nonce used during encryption
            encryption_key: 32-byte encryption key (from derive_encryption_key)

        Returns:
            Decrypted password as string

        Raises:
            ValueError: If encryption_key is not 32 bytes
            cryptography.exceptions.InvalidTag: If authentication fails
                (indicates tampering or wrong key)
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes (256 bits)")

        aesgcm = AESGCM(encryption_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext.decode('utf-8')
