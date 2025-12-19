"""
Cryptographic utilities for secure password storage.
Uses PBKDF2 for key derivation and Fernet (AES) for encryption.
"""

import base64
import hashlib
import os
import secrets
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Security parameters
SALT_LENGTH = 32
ITERATIONS = 480000  # OWASP recommended minimum for PBKDF2-SHA256


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from the master password using PBKDF2.

    Args:
        master_password: The user's master password
        salt: Random salt for key derivation

    Returns:
        A 32-byte key suitable for Fernet encryption
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def hash_password(password: str, salt: bytes) -> str:
    """
    Create a hash of the password for verification purposes.

    Args:
        password: Password to hash
        salt: Salt for hashing

    Returns:
        Hex-encoded hash string
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        ITERATIONS
    ).hex()


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypt data using Fernet symmetric encryption.

    Args:
        data: String data to encrypt
        key: Encryption key derived from master password

    Returns:
        Encrypted bytes
    """
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypt data using Fernet symmetric encryption.

    Args:
        encrypted_data: Encrypted bytes
        key: Encryption key derived from master password

    Returns:
        Decrypted string

    Raises:
        InvalidToken: If decryption fails (wrong password or corrupted data)
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()


def verify_master_password(password: str, salt: bytes, stored_hash: str) -> bool:
    """
    Verify a master password against stored hash.

    Args:
        password: Password to verify
        salt: Salt used for hashing
        stored_hash: Previously stored password hash

    Returns:
        True if password matches, False otherwise
    """
    computed_hash = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)
