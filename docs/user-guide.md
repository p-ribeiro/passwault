# Passwault User Guide

A comprehensive guide to installing, configuring, and using Passwault — a local-first CLI password manager with AES-256-GCM encryption and image steganography.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Portable USB Mode](#portable-usb-mode)
- [Command Reference](#command-reference)
  - [Authentication](#authentication)
  - [Password Management](#password-management)
  - [Password Generation](#password-generation)
  - [Image Steganography](#image-steganography)
  - [Backup](#backup)
  - [Migration](#migration)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.14 or later
- [uv](https://docs.astral.sh/uv/) package manager (recommended)

### Install from source

```bash
git clone https://github.com/your-org/passwault.git
cd passwault
uv sync
uv pip install -e .
```

### Verify installation

```bash
passwault --help
```

You should see the top-level help output listing all available commands.

### Optional: clipboard support

Passwault can copy generated passwords to the clipboard. Install the appropriate tool for your platform:

| Platform | Tool | Install |
|----------|------|---------|
| Linux (X11) | `xclip` (preferred) or `xsel` | `sudo apt install xclip` |
| macOS | `pbcopy` | Pre-installed |
| WSL2 | `clip.exe` | Works automatically with Windows interop |

If no clipboard tool is available, passwords are still printed to the terminal.

### Optional: PostgreSQL support

To use PostgreSQL instead of the default SQLite backend:

```bash
uv pip install -e ".[postgres]"
```

This installs the `psycopg2-binary` driver.

---

## Quick Start

### 1. Register an account

```bash
passwault auth register -u alice
```

You will be prompted to enter and confirm a master password. This password is used for authentication and to derive the encryption key for your stored passwords.

### 2. Log in

```bash
passwault auth login -u alice
```

Enter your master password when prompted. A session is created that lasts 10 minutes.

### 3. Store your first password

```bash
passwault add -n github -p 'my-secret-password' -u alice@example.com -w https://github.com
```

### 4. Retrieve it

```bash
passwault get -n github
```

### 5. Generate a secure password

```bash
passwault generate -l 24
```

Or generate and save interactively:

```bash
passwault generate --save -l 20
```

---

## Configuration

Passwault uses a configuration fallback chain to determine the database backend:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (highest) | `DATABASE_URL` environment variable | Direct connection string |
| 2 | `~/.config/passwault/.env` | Config file with `DATABASE_URL=...` |
| 3 (default) | Automatic SQLite | `~/.local/share/passwault/passwault.db` |

### SQLite (default)

No configuration needed. The database is created automatically at `~/.local/share/passwault/passwault.db`.

### PostgreSQL

Set the `DATABASE_URL` environment variable or add it to `~/.config/passwault/.env`:

```bash
# Environment variable
export DATABASE_URL="postgresql://user:pass@localhost:5432/passwault"

# Or config file
mkdir -p ~/.config/passwault
echo 'DATABASE_URL=postgresql://user:pass@localhost:5432/passwault' > ~/.config/passwault/.env
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | SQLite at `~/.local/share/passwault/passwault.db` |
| `PASSWAULT_BACKUP_DIR` | Custom backup directory | `~/.local/share/passwault/backups/` |

### Data directories

| Mode | Data directory |
|------|---------------|
| Normal | `~/.local/share/passwault/` |
| Portable | `<executable_dir>/passwault-data/` |

---

## Portable USB Mode

Passwault can be built as a portable executable that runs from a USB drive with all data stored alongside the executable.

### Build the portable executable

```bash
make build-portable
```

This uses PyInstaller to create a self-contained build in `dist/passwault/` with launcher scripts for Linux/macOS (`run.sh`) and Windows (`run.bat`).

### Deploy to USB

Copy the entire `dist/passwault/` folder to your USB drive.

### Run from USB

**Linux/macOS:**
```bash
./run.sh
```

**Windows:**
```
run.bat
```

The launcher scripts automatically pass the `--portable` flag, which stores all data (database, session, backups) in a `passwault-data/` directory next to the executable.

### Migrate existing data to portable

If you have an existing Passwault database (SQLite or PostgreSQL) and want to export it for portable use:

```bash
passwault migrate --to-sqlite -o /path/to/usb/passwault/passwault-data/passwault.db
```

This copies all users and encrypted passwords to a new SQLite file. Encrypted data is transferred as-is — no master password needed for migration.

---

## Command Reference

### Authentication

#### `auth register` — Create a new user account

```bash
passwault auth register -u <username> [-p <password>] [-e <email>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-u`, `--username` | Yes | Your username |
| `-p`, `--password` | No | Master password (prompted with masking if omitted) |
| `-e`, `--email` | No | Email address |

If `-p` is omitted, you are prompted to enter and confirm your password with input masking.

**Examples:**

```bash
# Interactive (recommended — password not visible in shell history)
passwault auth register -u alice

# With all options
passwault auth register -u alice -p 'MyStr0ngP@ss!' -e alice@example.com
```

#### `auth login` — Log in to your account

```bash
passwault auth login -u <username> [-p <password>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-u`, `--username` | Yes | Your username |
| `-p`, `--password` | No | Master password (prompted if omitted) |

Creates a session that expires after 10 minutes of inactivity. The encryption key is cached in memory for the duration of the session.

**Example:**

```bash
passwault auth login -u alice
```

#### `auth logout` — End your session

```bash
passwault auth logout
```

Clears the session, removes the encryption key from memory, and deletes the session file from disk.

#### `auth change-password` — Change your master password

```bash
passwault auth change-password [-o <old-password>] [-n <new-password>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-o`, `--old-password` | No | Current master password (prompted if omitted) |
| `-n`, `--new-password` | No | New master password (prompted if omitted) |

Requires an active session. Re-encrypts all stored passwords with the new key in a single database transaction.

**Example:**

```bash
passwault auth change-password
```

---

### Password Management

All password management commands require an active session (you must be logged in).

#### `add` — Store a new password

```bash
passwault add -n <resource-name> -p <password> [-u <username>] [-w <website>] [-d <description>] [-t <tags>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-n`, `--resource-name` | Yes | Identifier for this entry (e.g., `github`, `aws-prod`) |
| `-p`, `--password` | Yes | Password to encrypt and store |
| `-u`, `--username` | No | Username associated with this password |
| `-w`, `--website` | No | Website URL |
| `-d`, `--description` | No | Description |
| `-t`, `--tags` | No | Comma-separated tags |

Each user can have only one entry per resource name.

**Examples:**

```bash
# Minimal
passwault add -n github -p 's3cretP@ss'

# With all metadata
passwault add -n github -p 's3cretP@ss' -u alice@example.com -w https://github.com -d "Personal account" -t "dev,code"
```

#### `get` — Retrieve password(s)

```bash
passwault get [-n <resource-name>] [-u <username>] [-a]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-n`, `--resource-name` | No | Get a specific password by resource name |
| `-u`, `--username` | No | Get all passwords for a username |
| `-a`, `--all` | No | Get all stored passwords |

Provide exactly one of `-n`, `-u`, or `-a`.

**Examples:**

```bash
# Get a specific password
passwault get -n github

# Get all passwords for a username
passwault get -u alice@example.com

# List all passwords
passwault get -a
```

#### `update` — Update an existing password

```bash
passwault update -n <resource-name> -p <new-password> [-u <username>] [-w <website>] [-d <description>] [-t <tags>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-n`, `--resource-name` | Yes | Resource name to update |
| `-p`, `--password` | Yes | New password |
| `-u`, `--username` | No | Update username |
| `-w`, `--website` | No | Update website |
| `-d`, `--description` | No | Update description |
| `-t`, `--tags` | No | Update tags |

Only the provided optional fields are updated; others remain unchanged.

**Example:**

```bash
passwault update -n github -p 'newP@ssw0rd!' -u new-email@example.com
```

#### `delete` — Remove a password entry

```bash
passwault delete -n <resource-name>
```

| Option | Required | Description |
|--------|----------|-------------|
| `-n`, `--resource-name` | Yes | Resource name to delete |

**Example:**

```bash
passwault delete -n github
```

---

### Password Generation

#### `generate` — Generate a secure random password

```bash
passwault generate [-l <length>] [--no-symbols] [--no-digits] [--no-uppercase] [--save]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-l`, `--length` | `16` | Password length |
| `--no-symbols` | Off | Exclude symbols (`!`, `#`, `$`, `%`, `&`) |
| `--no-digits` | Off | Exclude digits |
| `--no-uppercase` | Off | Exclude uppercase letters |
| `--save` | Off | Interactive mode: regenerate, then save to database |

Without `--save`, the generated password is printed to the terminal. No login required.

With `--save`, you enter an interactive loop (requires login):

- Press **r** to regenerate
- Press **s** to save to the database (you will be prompted for resource name and optional metadata)
- Press **q** to quit without saving

After saving, the password is automatically copied to the clipboard if a clipboard tool is available.

**Examples:**

```bash
# Generate a 24-character password
passwault generate -l 24

# Generate without symbols
passwault generate -l 20 --no-symbols

# Generate and save interactively
passwault generate --save -l 18
```

---

### Image Steganography

Passwault can hide passwords inside images using LSB (Least Significant Bit) encoding. The password is embedded in the pixel data and can only be extracted by an authenticated user.

#### `imagepass encode` — Hide a password in an image

```bash
passwault imagepass encode <image_path> -p <password>
```

| Argument/Option | Required | Description |
|-----------------|----------|-------------|
| `image_path` | Yes | Path to the source image |
| `-p`, `--password` | Yes | Password to hide |

The modified image is saved to `data/results/` with the same filename.

**Supported formats:** PNG, BMP, TIFF, GIF (lossless formats only). JPEG is **not** supported because lossy compression destroys the embedded data.

**Example:**

```bash
passwault imagepass encode photo.png -p 'hidden-secret'
```

#### `imagepass decode` — Extract a password from an image

```bash
passwault imagepass decode <image_path>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `image_path` | Yes | Path to the image containing a hidden password |

**Example:**

```bash
passwault imagepass decode data/results/photo.png
```

---

### Backup

#### `backup create` — Create a database backup

```bash
passwault backup create [--no-compress] [-o <output-dir>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--no-compress` | Off | Don't gzip-compress the backup |
| `-o`, `--output-dir` | `~/.local/share/passwault/backups/` | Custom output directory |

Backups are timestamped (e.g., `passwault_20260210_143022.db.gz`).

- **SQLite:** copies the database file directly
- **PostgreSQL:** runs `pg_dump` with `--format=plain --no-owner --no-privileges`

**Example:**

```bash
passwault backup create
passwault backup create --no-compress -o /mnt/usb/backups
```

#### `backup list` — List available backups

```bash
passwault backup list
```

Shows all backups sorted by date (newest first) with file name, size, and modification time.

#### `backup restore` — Restore from a backup

```bash
passwault backup restore <backup_file> [-y]
```

| Argument/Option | Required | Description |
|-----------------|----------|-------------|
| `backup_file` | Yes | Path to backup file or filename in backup directory |
| `-y`, `--yes` | No | Skip confirmation prompt |

For SQLite restores, a `.bak` copy of the current database is created before restoring.

**Example:**

```bash
passwault backup restore passwault_20260210_143022.db.gz
passwault backup restore /path/to/backup.db.gz -y
```

#### `backup cleanup` — Remove old backups

```bash
passwault backup cleanup [--retention-days <days>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--retention-days` | `30` | Keep backups from the last N days |

**Example:**

```bash
passwault backup cleanup --retention-days 7
```

---

### Migration

#### `migrate --to-sqlite` — Export to portable SQLite

```bash
passwault migrate --to-sqlite -o <output-path>
```

| Option | Required | Description |
|--------|----------|-------------|
| `--to-sqlite` | Yes | Migrate to SQLite format |
| `-o`, `--output` | Yes | Output path for the SQLite file |

Copies all users and encrypted passwords to a new SQLite database file. Encrypted data is transferred as-is — no decryption or master password is needed. The output file must not already exist (safety guard).

**Example:**

```bash
passwault migrate --to-sqlite -o ~/usb/passwault-data/passwault.db
```

---

## Security

### Encryption overview

Passwault uses a layered encryption approach:

1. **Authentication:** Your master password is hashed with **bcrypt** (cost factor 12, automatic salt) and stored for login verification.

2. **Key derivation:** A separate 32-byte encryption key is derived from your master password using **PBKDF2-HMAC-SHA256** with 600,000 iterations (OWASP 2023 recommendation) and a unique random salt per user.

3. **Password encryption:** Each stored password is encrypted with **AES-256-GCM**, which provides both confidentiality and integrity (authenticated encryption). Every password entry has its own random 12-byte nonce.

### What is stored on disk

| Data | Storage | Notes |
|------|---------|-------|
| Master password | bcrypt hash only | Original password never stored |
| PBKDF2 salt | 32 random bytes per user | Used to derive encryption key |
| Encryption key | **Never stored on disk** | Derived on login, cached in memory for session duration |
| Stored passwords | AES-256-GCM ciphertext + nonce | Each entry has a unique nonce |
| Session data | Fernet-encrypted file | Contains user ID, username, timestamp, and encryption key |

### Session management

- Sessions expire after **10 minutes** of inactivity
- The encryption key is cached in memory and included (Fernet-encrypted) in the session file
- On logout, the session file and encryption key file are deleted from disk
- The `@require_auth` decorator enforces authentication on all password operations

### Threat model

**Protected against:**
- Database theft — passwords are AES-256-GCM encrypted; attacker needs the master password
- Brute-force attacks — bcrypt hashing + 600K PBKDF2 iterations make offline attacks expensive
- Data tampering — GCM authentication tags detect any modification to ciphertext
- Timing attacks — bcrypt uses constant-time comparison

**Out of scope:**
- Keyloggers or malware on the host machine
- Shoulder surfing (passwords are printed to terminal)
- Memory forensics while the session is active

### Steganography security

Image steganography uses LSB encoding with a variable-spacing key embedded in the image header. The header includes a CRC32 integrity check. This provides concealment, not cryptographic security — for sensitive data, encrypt the password before embedding it in an image.

---

## Troubleshooting

### "Authentication required" error

You need to log in before using password commands:

```bash
passwault auth login -u <username>
```

### "Session expired" error

Sessions expire after 10 minutes of inactivity. Log in again:

```bash
passwault auth login -u <username>
```

### Clipboard not working

Verify your clipboard tool is installed:

```bash
# Linux (X11)
which xclip || which xsel

# macOS
which pbcopy

# WSL2 — ensure Windows interop is enabled
which clip.exe
```

If no clipboard tool is available, passwords are still displayed in the terminal.

### "Image format not supported" / JPEG errors

Image steganography only works with **lossless** image formats:

- **Supported:** PNG, BMP, TIFF, GIF
- **Not supported:** JPEG, WebP (lossy compression destroys embedded data)

Convert your image to PNG before encoding:

```bash
convert photo.jpg photo.png
passwault imagepass encode photo.png -p 'secret'
```

### "Message too large to encode in the image"

The image does not have enough pixels to embed the password. Use a larger image or a shorter password. The capacity depends on the number of pixels multiplied by the number of color channels.

### Database locked (SQLite)

If you see a "database is locked" error, ensure no other Passwault process is running. SQLite uses file-level locking and only supports one writer at a time.

### PostgreSQL connection errors

Verify your `DATABASE_URL` is correct and the PostgreSQL server is running:

```bash
echo $DATABASE_URL
psql "$DATABASE_URL" -c "SELECT 1"
```

### Migration fails with "File already exists"

The `migrate --to-sqlite` command refuses to overwrite existing files as a safety measure. Remove or rename the existing file first:

```bash
mv existing.db existing.db.bak
passwault migrate --to-sqlite -o existing.db
```
