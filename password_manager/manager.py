"""
Password Manager core logic.
Provides high-level operations for managing password entries.
"""

import secrets
import string
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
from uuid import uuid4

from .storage import VaultStorage


@dataclass
class PasswordEntry:
    """Represents a single password entry."""
    id: str
    name: str
    website: str
    username: str
    password: str
    notes: str
    created_at: str
    updated_at: str

    @classmethod
    def create(cls, name: str, website: str, username: str, password: str, notes: str = "") -> "PasswordEntry":
        """Create a new password entry with generated ID and timestamps."""
        now = datetime.utcnow().isoformat()
        return cls(
            id=str(uuid4()),
            name=name,
            website=website,
            username=username,
            password=password,
            notes=notes,
            created_at=now,
            updated_at=now
        )

    def to_dict(self) -> dict:
        """Convert entry to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        """Create entry from dictionary."""
        return cls(**data)


class PasswordManager:
    """Main password manager class."""

    def __init__(self, storage: Optional[VaultStorage] = None):
        """
        Initialize the password manager.

        Args:
            storage: VaultStorage instance. Creates default if not provided.
        """
        self.storage = storage or VaultStorage()
        self._key: Optional[bytes] = None
        self._entries: list[PasswordEntry] = []

    @property
    def is_unlocked(self) -> bool:
        """Check if the vault is currently unlocked."""
        return self._key is not None

    def vault_exists(self) -> bool:
        """Check if a vault exists."""
        return self.storage.vault_exists()

    def create_vault(self, master_password: str) -> None:
        """
        Create a new vault with the given master password.

        Args:
            master_password: The master password for the vault
        """
        self._key = self.storage.create_vault(master_password)
        self._entries = []

    def unlock(self, master_password: str) -> bool:
        """
        Unlock the vault with the master password.

        Args:
            master_password: The master password

        Returns:
            True if unlock was successful
        """
        try:
            self._key = self.storage.unlock_vault(master_password)
            self._load_entries()
            return True
        except ValueError:
            return False

    def lock(self) -> None:
        """Lock the vault, clearing all sensitive data from memory."""
        self._key = None
        self._entries = []

    def _load_entries(self) -> None:
        """Load entries from storage."""
        if not self._key:
            raise RuntimeError("Vault is locked")
        raw_entries = self.storage.get_entries(self._key)
        self._entries = [PasswordEntry.from_dict(e) for e in raw_entries]

    def _save_entries(self) -> None:
        """Save entries to storage."""
        if not self._key:
            raise RuntimeError("Vault is locked")
        raw_entries = [e.to_dict() for e in self._entries]
        self.storage.save_entries(raw_entries, self._key)

    def add_entry(self, name: str, website: str, username: str, password: str, notes: str = "") -> PasswordEntry:
        """
        Add a new password entry.

        Args:
            name: Friendly name for the entry
            website: Website URL
            username: Login username
            password: Password
            notes: Optional notes

        Returns:
            The created entry
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")

        entry = PasswordEntry.create(name, website, username, password, notes)
        self._entries.append(entry)
        self._save_entries()
        return entry

    def get_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Get an entry by ID.

        Args:
            entry_id: The entry ID

        Returns:
            The entry or None if not found
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")

        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        return None

    def update_entry(self, entry_id: str, **kwargs) -> Optional[PasswordEntry]:
        """
        Update an existing entry.

        Args:
            entry_id: The entry ID
            **kwargs: Fields to update (name, website, username, password, notes)

        Returns:
            The updated entry or None if not found
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")

        for i, entry in enumerate(self._entries):
            if entry.id == entry_id:
                # Update allowed fields
                for field in ['name', 'website', 'username', 'password', 'notes']:
                    if field in kwargs:
                        setattr(entry, field, kwargs[field])
                entry.updated_at = datetime.utcnow().isoformat()
                self._entries[i] = entry
                self._save_entries()
                return entry
        return None

    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete an entry by ID.

        Args:
            entry_id: The entry ID

        Returns:
            True if deleted, False if not found
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")

        for i, entry in enumerate(self._entries):
            if entry.id == entry_id:
                del self._entries[i]
                self._save_entries()
                return True
        return False

    def list_entries(self) -> list[PasswordEntry]:
        """
        Get all password entries.

        Returns:
            List of all entries
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")
        return self._entries.copy()

    def search_entries(self, query: str) -> list[PasswordEntry]:
        """
        Search entries by name, website, or username.

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching entries
        """
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked")

        query_lower = query.lower()
        results = []
        for entry in self._entries:
            if (query_lower in entry.name.lower() or
                query_lower in entry.website.lower() or
                query_lower in entry.username.lower()):
                results.append(entry)
        return results

    @staticmethod
    def generate_password(length: int = 16, include_symbols: bool = True) -> str:
        """
        Generate a secure random password.

        Args:
            length: Password length (default 16)
            include_symbols: Include special characters

        Returns:
            Generated password
        """
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Ensure at least one of each required character type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

        # Fill the rest randomly
        remaining_length = length - len(password)
        password.extend(secrets.choice(chars) for _ in range(remaining_length))

        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    def delete_vault(self) -> None:
        """Delete the entire vault."""
        self.lock()
        self.storage.delete_vault()
