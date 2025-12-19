#!/usr/bin/env python3
"""
Password Manager CLI
A simple and secure password management application.
"""

import getpass
import sys
from typing import Optional

from .manager import PasswordManager, PasswordEntry


class PasswordManagerCLI:
    """Command-line interface for the password manager."""

    def __init__(self):
        self.manager = PasswordManager()

    def run(self) -> None:
        """Run the password manager CLI."""
        self._print_header()

        if not self.manager.vault_exists():
            self._setup_new_vault()
        else:
            if not self._login():
                print("\nToo many failed attempts. Exiting.")
                sys.exit(1)

        self._main_menu()

    def _print_header(self) -> None:
        """Print application header."""
        print("\n" + "=" * 50)
        print("       SECURE PASSWORD MANAGER")
        print("=" * 50)

    def _setup_new_vault(self) -> None:
        """Set up a new vault for first-time users."""
        print("\nNo vault found. Let's create one!")
        print("-" * 40)

        while True:
            password = getpass.getpass("Create master password: ")
            if len(password) < 8:
                print("Password must be at least 8 characters.")
                continue

            confirm = getpass.getpass("Confirm master password: ")
            if password != confirm:
                print("Passwords don't match. Try again.")
                continue

            break

        print("\nCreating vault...")
        self.manager.create_vault(password)
        print("Vault created successfully!")

    def _login(self) -> bool:
        """Handle login with retry logic."""
        print("\nEnter your master password to unlock the vault.")
        print("-" * 40)

        max_attempts = 3
        for attempt in range(max_attempts):
            password = getpass.getpass("Master password: ")
            if self.manager.unlock(password):
                print("\nVault unlocked successfully!")
                return True
            remaining = max_attempts - attempt - 1
            if remaining > 0:
                print(f"Incorrect password. {remaining} attempt(s) remaining.")

        return False

    def _main_menu(self) -> None:
        """Display and handle the main menu."""
        while True:
            print("\n" + "-" * 40)
            print("MAIN MENU")
            print("-" * 40)
            print("1. List all entries")
            print("2. Search entries")
            print("3. Add new entry")
            print("4. View entry details")
            print("5. Edit entry")
            print("6. Delete entry")
            print("7. Generate password")
            print("8. Lock vault")
            print("9. Exit")
            print("-" * 40)

            choice = input("Choose option (1-9): ").strip()

            if choice == "1":
                self._list_entries()
            elif choice == "2":
                self._search_entries()
            elif choice == "3":
                self._add_entry()
            elif choice == "4":
                self._view_entry()
            elif choice == "5":
                self._edit_entry()
            elif choice == "6":
                self._delete_entry()
            elif choice == "7":
                self._generate_password()
            elif choice == "8":
                self._lock_vault()
                break
            elif choice == "9":
                self._exit()
                break
            else:
                print("Invalid option. Please choose 1-9.")

    def _list_entries(self) -> None:
        """List all password entries."""
        entries = self.manager.list_entries()
        if not entries:
            print("\nNo entries found. Add some entries first!")
            return

        print("\n" + "=" * 60)
        print(f"{'#':<4} {'NAME':<20} {'WEBSITE':<25} {'USERNAME':<15}")
        print("=" * 60)
        for i, entry in enumerate(entries, 1):
            name = entry.name[:18] + ".." if len(entry.name) > 20 else entry.name
            website = entry.website[:23] + ".." if len(entry.website) > 25 else entry.website
            username = entry.username[:13] + ".." if len(entry.username) > 15 else entry.username
            print(f"{i:<4} {name:<20} {website:<25} {username:<15}")
        print("=" * 60)
        print(f"Total: {len(entries)} entries")

    def _search_entries(self) -> None:
        """Search for entries."""
        query = input("\nSearch query: ").strip()
        if not query:
            print("Search cancelled.")
            return

        results = self.manager.search_entries(query)
        if not results:
            print(f"No entries found matching '{query}'")
            return

        print(f"\nFound {len(results)} matching entries:")
        print("-" * 60)
        for i, entry in enumerate(results, 1):
            print(f"{i}. {entry.name} ({entry.website})")

    def _add_entry(self) -> None:
        """Add a new password entry."""
        print("\n--- Add New Entry ---")

        name = input("Name (e.g., 'Gmail Account'): ").strip()
        if not name:
            print("Name is required. Entry not created.")
            return

        website = input("Website URL: ").strip()
        username = input("Username/Email: ").strip()

        # Option to generate password
        gen_choice = input("Generate password? (y/n): ").strip().lower()
        if gen_choice == 'y':
            length = input("Password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            symbols = input("Include symbols? (y/n, default y): ").strip().lower() != 'n'
            password = self.manager.generate_password(length, symbols)
            print(f"Generated password: {password}")
        else:
            password = getpass.getpass("Password: ")

        notes = input("Notes (optional): ").strip()

        entry = self.manager.add_entry(name, website, username, password, notes)
        print(f"\nEntry '{entry.name}' added successfully!")

    def _view_entry(self) -> None:
        """View details of an entry."""
        entry = self._select_entry("View")
        if not entry:
            return

        print("\n" + "=" * 50)
        print(f"Name:     {entry.name}")
        print(f"Website:  {entry.website}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        if entry.notes:
            print(f"Notes:    {entry.notes}")
        print(f"Created:  {entry.created_at}")
        print(f"Updated:  {entry.updated_at}")
        print("=" * 50)

    def _edit_entry(self) -> None:
        """Edit an existing entry."""
        entry = self._select_entry("Edit")
        if not entry:
            return

        print("\n--- Edit Entry ---")
        print("(Press Enter to keep current value)")

        name = input(f"Name [{entry.name}]: ").strip() or entry.name
        website = input(f"Website [{entry.website}]: ").strip() or entry.website
        username = input(f"Username [{entry.username}]: ").strip() or entry.username

        change_password = input("Change password? (y/n): ").strip().lower()
        if change_password == 'y':
            gen_choice = input("Generate password? (y/n): ").strip().lower()
            if gen_choice == 'y':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length.isdigit() else 16
                password = self.manager.generate_password(length)
                print(f"Generated password: {password}")
            else:
                password = getpass.getpass("New password: ")
        else:
            password = entry.password

        notes = input(f"Notes [{entry.notes}]: ").strip()
        if not notes and entry.notes:
            keep_notes = input("Clear notes? (y/n): ").strip().lower()
            notes = "" if keep_notes == 'y' else entry.notes

        self.manager.update_entry(
            entry.id,
            name=name,
            website=website,
            username=username,
            password=password,
            notes=notes
        )
        print("\nEntry updated successfully!")

    def _delete_entry(self) -> None:
        """Delete an entry."""
        entry = self._select_entry("Delete")
        if not entry:
            return

        confirm = input(f"Are you sure you want to delete '{entry.name}'? (yes/no): ").strip().lower()
        if confirm == 'yes':
            self.manager.delete_entry(entry.id)
            print("Entry deleted.")
        else:
            print("Deletion cancelled.")

    def _select_entry(self, action: str) -> Optional[PasswordEntry]:
        """Helper to select an entry from the list."""
        entries = self.manager.list_entries()
        if not entries:
            print("\nNo entries found.")
            return None

        self._list_entries()
        selection = input(f"\n{action} entry number (or 'c' to cancel): ").strip()

        if selection.lower() == 'c':
            return None

        try:
            index = int(selection) - 1
            if 0 <= index < len(entries):
                return entries[index]
            else:
                print("Invalid entry number.")
                return None
        except ValueError:
            print("Invalid input.")
            return None

    def _generate_password(self) -> None:
        """Generate a random password."""
        print("\n--- Password Generator ---")
        length = input("Password length (default 16): ").strip()
        length = int(length) if length.isdigit() else 16
        symbols = input("Include symbols? (y/n, default y): ").strip().lower() != 'n'

        password = self.manager.generate_password(length, symbols)
        print(f"\nGenerated password: {password}")
        print("(Password not saved - use Add Entry to save)")

    def _lock_vault(self) -> None:
        """Lock the vault."""
        self.manager.lock()
        print("\nVault locked. Goodbye!")

    def _exit(self) -> None:
        """Exit the application."""
        self.manager.lock()
        print("\nVault locked. Goodbye!")


def main():
    """Entry point for the password manager."""
    try:
        cli = PasswordManagerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
