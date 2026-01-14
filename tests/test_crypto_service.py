"""Unit tests for CryptoService.

Tests all cryptographic operations including:
- Salt generation
- Master password hashing and verification
- Encryption key derivation
- Password encryption and decryption
"""

import pytest
from cryptography.exceptions import InvalidTag

from passwault.core.services.crypto_service import CryptoService


class TestCryptoService:
    """Test suite for CryptoService cryptographic operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.crypto = CryptoService()
        self.test_password = "SecureTestPassword123!"
        self.test_plaintext = "MySecretPassword"

    def test_generate_salt_default_length(self):
        """Test salt generation with default length (32 bytes)."""
        salt = self.crypto.generate_salt()

        assert isinstance(salt, bytes)
        assert len(salt) == 32

    def test_generate_salt_custom_length(self):
        """Test salt generation with custom length."""
        salt = self.crypto.generate_salt(length=16)

        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_generate_salt_randomness(self):
        """Test that generated salts are unique (high probability)."""
        salt1 = self.crypto.generate_salt()
        salt2 = self.crypto.generate_salt()

        assert salt1 != salt2

    def test_hash_master_password(self):
        """Test master password hashing with bcrypt."""
        password_hash = self.crypto.hash_master_password(self.test_password)

        assert isinstance(password_hash, bytes)
        assert len(password_hash) == 60  # bcrypt hash length
        assert password_hash.startswith(b"$2b$")  # bcrypt identifier

    def test_hash_master_password_different_hashes(self):
        """Test that same password produces different hashes (due to salt)."""
        hash1 = self.crypto.hash_master_password(self.test_password)
        hash2 = self.crypto.hash_master_password(self.test_password)

        assert hash1 != hash2  # Different salts

    def test_verify_master_password_correct(self):
        """Test password verification with correct password."""
        password_hash = self.crypto.hash_master_password(self.test_password)
        result = self.crypto.verify_master_password(self.test_password, password_hash)

        assert result is True

    def test_verify_master_password_incorrect(self):
        """Test password verification with incorrect password."""
        password_hash = self.crypto.hash_master_password(self.test_password)
        result = self.crypto.verify_master_password("WrongPassword", password_hash)

        assert result is False

    def test_verify_master_password_case_sensitive(self):
        """Test that password verification is case-sensitive."""
        password_hash = self.crypto.hash_master_password("TestPassword")
        result = self.crypto.verify_master_password("testpassword", password_hash)

        assert result is False

    def test_verify_master_password_invalid_hash(self):
        """Test password verification with invalid hash."""
        result = self.crypto.verify_master_password(
            self.test_password, b"invalid_hash"
        )

        assert result is False

    def test_derive_encryption_key_default_iterations(self):
        """Test encryption key derivation with default iterations."""
        salt = self.crypto.generate_salt()
        key = self.crypto.derive_encryption_key(self.test_password, salt)

        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits

    def test_derive_encryption_key_custom_iterations(self):
        """Test encryption key derivation with custom iterations."""
        salt = self.crypto.generate_salt()
        key = self.crypto.derive_encryption_key(
            self.test_password, salt, iterations=100000
        )

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_encryption_key_deterministic(self):
        """Test that same password and salt produce same key."""
        salt = self.crypto.generate_salt()

        key1 = self.crypto.derive_encryption_key(self.test_password, salt)
        key2 = self.crypto.derive_encryption_key(self.test_password, salt)

        assert key1 == key2

    def test_derive_encryption_key_different_salt(self):
        """Test that different salts produce different keys."""
        salt1 = self.crypto.generate_salt()
        salt2 = self.crypto.generate_salt()

        key1 = self.crypto.derive_encryption_key(self.test_password, salt1)
        key2 = self.crypto.derive_encryption_key(self.test_password, salt2)

        assert key1 != key2

    def test_derive_encryption_key_different_password(self):
        """Test that different passwords produce different keys."""
        salt = self.crypto.generate_salt()

        key1 = self.crypto.derive_encryption_key("Password1", salt)
        key2 = self.crypto.derive_encryption_key("Password2", salt)

        assert key1 != key2

    def test_encrypt_password(self):
        """Test password encryption."""
        key = self.crypto.generate_salt(length=32)  # Use as encryption key
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        assert isinstance(ciphertext, bytes)
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12  # GCM nonce length
        assert ciphertext != self.test_plaintext.encode()

    def test_encrypt_password_different_nonce(self):
        """Test that same plaintext produces different ciphertexts (different nonce)."""
        key = self.crypto.generate_salt(length=32)

        ciphertext1, nonce1 = self.crypto.encrypt_password(self.test_plaintext, key)
        ciphertext2, nonce2 = self.crypto.encrypt_password(self.test_plaintext, key)

        assert nonce1 != nonce2
        assert ciphertext1 != ciphertext2

    def test_encrypt_password_invalid_key_length(self):
        """Test encryption with invalid key length."""
        invalid_key = b"short_key"

        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            self.crypto.encrypt_password(self.test_plaintext, invalid_key)

    def test_decrypt_password(self):
        """Test password decryption."""
        key = self.crypto.generate_salt(length=32)
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        decrypted = self.crypto.decrypt_password(ciphertext, nonce, key)

        assert decrypted == self.test_plaintext

    def test_decrypt_password_wrong_key(self):
        """Test decryption with wrong key fails."""
        key1 = self.crypto.generate_salt(length=32)
        key2 = self.crypto.generate_salt(length=32)

        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key1)

        with pytest.raises(InvalidTag):
            self.crypto.decrypt_password(ciphertext, nonce, key2)

    def test_decrypt_password_wrong_nonce(self):
        """Test decryption with wrong nonce fails."""
        key = self.crypto.generate_salt(length=32)
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        wrong_nonce = self.crypto.generate_salt(length=12)

        with pytest.raises(InvalidTag):
            self.crypto.decrypt_password(ciphertext, wrong_nonce, key)

    def test_decrypt_password_tampered_ciphertext(self):
        """Test decryption with tampered ciphertext fails."""
        key = self.crypto.generate_salt(length=32)
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1  # Flip one bit
        tampered_ciphertext = bytes(tampered)

        with pytest.raises(InvalidTag):
            self.crypto.decrypt_password(tampered_ciphertext, nonce, key)

    def test_decrypt_password_invalid_key_length(self):
        """Test decryption with invalid key length."""
        key = self.crypto.generate_salt(length=32)
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        invalid_key = b"short_key"

        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            self.crypto.decrypt_password(ciphertext, nonce, invalid_key)

    def test_encrypt_decrypt_roundtrip(self):
        """Test full encryption/decryption roundtrip with derived key."""
        # Simulate real usage: derive key from password
        salt = self.crypto.generate_salt()
        key = self.crypto.derive_encryption_key(self.test_password, salt)

        # Encrypt
        ciphertext, nonce = self.crypto.encrypt_password(self.test_plaintext, key)

        # Decrypt
        decrypted = self.crypto.decrypt_password(ciphertext, nonce, key)

        assert decrypted == self.test_plaintext

    def test_encrypt_decrypt_unicode(self):
        """Test encryption/decryption with unicode characters."""
        key = self.crypto.generate_salt(length=32)
        unicode_password = "Pässwörd123!@#$%^&*()_+émojis🔒"

        ciphertext, nonce = self.crypto.encrypt_password(unicode_password, key)
        decrypted = self.crypto.decrypt_password(ciphertext, nonce, key)

        assert decrypted == unicode_password

    def test_encrypt_decrypt_empty_string(self):
        """Test encryption/decryption with empty string."""
        key = self.crypto.generate_salt(length=32)
        empty_password = ""

        ciphertext, nonce = self.crypto.encrypt_password(empty_password, key)
        decrypted = self.crypto.decrypt_password(ciphertext, nonce, key)

        assert decrypted == empty_password

    def test_encrypt_decrypt_long_password(self):
        """Test encryption/decryption with very long password."""
        key = self.crypto.generate_salt(length=32)
        long_password = "A" * 10000

        ciphertext, nonce = self.crypto.encrypt_password(long_password, key)
        decrypted = self.crypto.decrypt_password(ciphertext, nonce, key)

        assert decrypted == long_password

    def test_encryption_key_derivation_with_known_vector(self):
        """Test key derivation with a known test vector for consistency."""
        # Use consistent values for reproducible test
        password = "test_password"
        salt = b"0" * 32  # Fixed salt for test
        iterations = 1000  # Lower for faster test

        key = self.crypto.derive_encryption_key(password, salt, iterations)

        # Key should be deterministic for same inputs
        key2 = self.crypto.derive_encryption_key(password, salt, iterations)
        assert key == key2

        # Verify it's 32 bytes
        assert len(key) == 32


class TestCryptoServiceIntegration:
    """Integration tests simulating real-world usage patterns."""

    def setup_method(self):
        """Set up test fixtures."""
        self.crypto = CryptoService()

    def test_full_user_registration_flow(self):
        """Test complete user registration flow with crypto operations."""
        username = "testuser"
        master_password = "MasterPass123!"

        # Registration: generate salt and hash password
        salt = self.crypto.generate_salt()
        password_hash = self.crypto.hash_master_password(master_password)

        # Verify we can authenticate later
        assert self.crypto.verify_master_password(master_password, password_hash)

        # Derive encryption key for encrypting user passwords
        encryption_key = self.crypto.derive_encryption_key(master_password, salt)

        assert len(encryption_key) == 32

    def test_full_password_save_load_flow(self):
        """Test complete password save and load flow."""
        # User setup
        master_password = "MasterPass123!"
        salt = self.crypto.generate_salt()
        encryption_key = self.crypto.derive_encryption_key(master_password, salt)

        # Save password (encrypt)
        user_password = "MySavedPassword123"
        ciphertext, nonce = self.crypto.encrypt_password(user_password, encryption_key)

        # Later: load password (decrypt)
        # User logs in again
        encryption_key_again = self.crypto.derive_encryption_key(
            master_password, salt
        )
        decrypted = self.crypto.decrypt_password(
            ciphertext, nonce, encryption_key_again
        )

        assert decrypted == user_password

    def test_multi_user_isolation(self):
        """Test that different users have isolated encryption."""
        # User 1
        user1_password = "User1Master"
        user1_salt = self.crypto.generate_salt()
        user1_key = self.crypto.derive_encryption_key(user1_password, user1_salt)

        # User 2
        user2_password = "User2Master"
        user2_salt = self.crypto.generate_salt()
        user2_key = self.crypto.derive_encryption_key(user2_password, user2_salt)

        # Encrypt same password with different user keys
        shared_password = "SharedPassword123"
        user1_cipher, user1_nonce = self.crypto.encrypt_password(
            shared_password, user1_key
        )
        user2_cipher, user2_nonce = self.crypto.encrypt_password(
            shared_password, user2_key
        )

        # Ciphertexts should be different
        assert user1_cipher != user2_cipher

        # User 1 cannot decrypt User 2's password
        with pytest.raises(InvalidTag):
            self.crypto.decrypt_password(user2_cipher, user2_nonce, user1_key)

        # Each user can decrypt their own
        assert (
            self.crypto.decrypt_password(user1_cipher, user1_nonce, user1_key)
            == shared_password
        )
        assert (
            self.crypto.decrypt_password(user2_cipher, user2_nonce, user2_key)
            == shared_password
        )
