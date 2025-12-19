# Secure Password Manager

A simple and lightweight command-line password manager for securely storing and retrieving your account credentials.

## Features

- **Secure Encryption**: Uses AES-256 encryption (via Fernet) to protect all stored passwords
- **Master Password Protection**: All data is encrypted with a key derived from your master password using PBKDF2 (480,000 iterations)
- **Secure Storage**: Encrypted vault stored locally with restricted file permissions
- **Password Generator**: Built-in secure random password generator
- **Search**: Quickly find entries by name, website, or username

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run the password manager
python -m password_manager
```

### First Run

On first run, you'll be prompted to create a master password. This password:
- Must be at least 8 characters long
- Is used to encrypt/decrypt all your stored passwords
- Cannot be recovered if forgotten (your data will be inaccessible)

### Main Menu Options

1. **List all entries** - View all stored password entries
2. **Search entries** - Search by name, website, or username
3. **Add new entry** - Store a new password (with optional password generation)
4. **View entry details** - See full details including password
5. **Edit entry** - Modify an existing entry
6. **Delete entry** - Remove an entry
7. **Generate password** - Create a secure random password
8. **Lock vault** - Lock the vault and exit
9. **Exit** - Exit the application

## Security Details

- **Key Derivation**: PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Encryption**: Fernet (AES-128-CBC with HMAC)
- **Salt**: 32 bytes of cryptographically secure random data
- **Storage**: Vault file permissions set to owner read/write only (0600)

## Data Location

The encrypted vault is stored at: `~/.password_manager/vault.json`

## Warning

⚠️ **Do not forget your master password!** There is no way to recover your data without it.
