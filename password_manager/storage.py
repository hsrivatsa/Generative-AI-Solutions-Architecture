"""
Storage module for persisting encrypted password data.
Uses a JSON-based format with all sensitive data encrypted.
"""

import base64
import json
import os
from pathlib import Path
from typing import Optional

from . import crypto


# Default storage location
DEFAULT_DATA_DIR = Path.home() / ".password_manager"
DATA_FILE = "vault.json"


class VaultStorage:
    """Handles reading and writing encrypted vault data."""

    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the vault storage.

        Args:
            data_dir: Directory to store vault data. Defaults to ~/.password_manager
        """
        self.data_dir = data_dir or DEFAULT_DATA_DIR
        self.data_file = self.data_dir / DATA_FILE

    def _ensure_data_dir(self) -> None:
        """Create data directory if it doesn't exist."""
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def vault_exists(self) -> bool:
        """Check if a vault already exists."""
        return self.data_file.exists()

    def create_vault(self, master_password: str) -> bytes:
        """
        Create a new vault with the given master password.

        Args:
            master_password: The master password for the vault

        Returns:
            The derived encryption key

        Raises:
            FileExistsError: If a vault already exists
        """
        if self.vault_exists():
            raise FileExistsError("Vault already exists. Delete it first to create a new one.")

        self._ensure_data_dir()

        # Generate salt and derive key
        salt = crypto.generate_salt()
        key = crypto.derive_key(master_password, salt)
        password_hash = crypto.hash_password(master_password, salt)

        # Create empty encrypted entries
        empty_entries = crypto.encrypt_data(json.dumps([]), key)

        vault_data = {
            "salt": base64.b64encode(salt).decode(),
            "password_hash": password_hash,
            "entries": base64.b64encode(empty_entries).decode()
        }

        self._write_vault(vault_data)
        return key

    def unlock_vault(self, master_password: str) -> bytes:
        """
        Unlock an existing vault with the master password.

        Args:
            master_password: The master password for the vault

        Returns:
            The derived encryption key

        Raises:
            FileNotFoundError: If no vault exists
            ValueError: If the password is incorrect
        """
        if not self.vault_exists():
            raise FileNotFoundError("No vault found. Create one first.")

        vault_data = self._read_vault()
        salt = base64.b64decode(vault_data["salt"])
        stored_hash = vault_data["password_hash"]

        if not crypto.verify_master_password(master_password, salt, stored_hash):
            raise ValueError("Incorrect master password.")

        return crypto.derive_key(master_password, salt)

    def get_entries(self, key: bytes) -> list:
        """
        Get all password entries from the vault.

        Args:
            key: The encryption key

        Returns:
            List of password entries
        """
        vault_data = self._read_vault()
        encrypted_entries = base64.b64decode(vault_data["entries"])
        decrypted = crypto.decrypt_data(encrypted_entries, key)
        return json.loads(decrypted)

    def save_entries(self, entries: list, key: bytes) -> None:
        """
        Save password entries to the vault.

        Args:
            entries: List of password entries
            key: The encryption key
        """
        vault_data = self._read_vault()
        encrypted_entries = crypto.encrypt_data(json.dumps(entries), key)
        vault_data["entries"] = base64.b64encode(encrypted_entries).decode()
        self._write_vault(vault_data)

    def delete_vault(self) -> None:
        """Delete the vault file."""
        if self.data_file.exists():
            self.data_file.unlink()

    def _read_vault(self) -> dict:
        """Read vault data from file."""
        with open(self.data_file, 'r') as f:
            return json.load(f)

    def _write_vault(self, data: dict) -> None:
        """Write vault data to file with secure permissions."""
        self._ensure_data_dir()
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
        # Set file permissions to owner read/write only
        os.chmod(self.data_file, 0o600)
