# Passwault Module Reference

Developer API reference for every public module, class, and function in the Passwault codebase.

---

## Table of Contents

- [Entry Point](#entry-point)
- [CLI](#cli)
- [Configuration](#configuration)
- [Database Models](#database-models)
- [Repositories](#repositories)
  - [UserRepository](#userrepository)
  - [PasswordRepository](#passwordrepository)
- [Services](#services)
  - [CryptoService](#cryptoservice)
  - [BackupService](#backupservice)
  - [MigrationService](#migrationservice)
- [Commands](#commands)
  - [Authentication](#authentication-commands)
  - [Password](#password-commands)
- [Utilities](#utilities)
  - [SessionManager](#sessionmanager)
  - [Decorators](#decorators)
  - [Custom Exceptions](#custom-exceptions)
  - [Logger](#logger)
  - [Data Directory](#data-directory)
  - [Clipboard](#clipboard)
  - [File Handler](#file-handler)
  - [Password Masking](#password-masking)
- [Imagepass](#imagepass)
  - [Embedder](#embedder)
  - [ImageHandler](#imagehandler)
  - [Config & Struct](#imagepass-config--struct)

---

## Entry Point

### `passwault/__main__.py`

CLI entry point. Initializes the database and launches the CLI interface.

#### `setup_portable_mode() -> None`

Check for `--portable` flag and configure the portable data directory. Must be called before any other imports that use `get_data_dir()`. Removes the `--portable` flag from `sys.argv` so argparse doesn't see it.

Called automatically at module load time.

#### `load_database_config() -> None`

Load database configuration with the following fallback chain:

1. `DATABASE_URL` environment variable (highest priority)
2. `~/.config/passwault/.env` config file (loaded via `python-dotenv`)
3. Local `.env` file (development fallback)

Called automatically at module load time, after `setup_portable_mode()`.

#### `main() -> None`

Main entry point for the Passwault CLI. Creates all database tables (if absent), initializes a `SessionManager`, expires any stale session, and launches the CLI.

Registered as the `passwault` console script entry point in `pyproject.toml`.

---

## CLI

### `passwault/core/cli.py`

CLI interface for all Passwault operations including authentication, password management, password generation, and image steganography.

#### `cli(args=None, session_manager=None)`

Main CLI entry point.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `args` | `list[str] \| None` | `None` | Command line arguments (`None` reads from `sys.argv`) |
| `session_manager` | `SessionManager \| None` | `None` | Session manager instance (created if `None`) |

**Returns:** Result of the executed command handler.

#### `handle_generate(args, session_manager) -> Any`

Handle the `generate` command. Routes to `generate_and_save()` if `--save` is set, otherwise calls `generate_password()`.

#### `handle_imagepass(args, session_manager) -> Any`

Handle imagepass encode/decode operations. Creates an `Embedder` instance and dispatches to `encode()` or `decode()`.

#### `handle_backup_create(args) -> None`

Handle `backup create` command. Creates a `BackupService` and calls `create_backup()`.

#### `handle_backup_list(args) -> None`

Handle `backup list` command. Lists backups with name, size (MB), and modification time.

#### `handle_backup_restore(args) -> None`

Handle `backup restore` command. Resolves the backup file path, prompts for confirmation (unless `-y`), and restores.

#### `handle_backup_cleanup(args) -> None`

Handle `backup cleanup` command. Removes backups older than the retention period.

#### `handle_migrate_to_sqlite(args) -> None`

Handle `migrate --to-sqlite` command. Calls `MigrationService().migrate_to_sqlite()`. Handles `FileExistsError` and generic exceptions.

---

## Configuration

### `passwault/core/config.py`

Application configuration management. Handles database URL parsing and environment-based configuration.

#### `class DatabaseType(Enum)`

Supported database backends.

| Value | String |
|-------|--------|
| `SQLITE` | `"sqlite"` |
| `POSTGRESQL` | `"postgresql"` |

#### `class Config`

Application configuration from environment variables.

**Class constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `ENV_DATABASE_URL` | `"DATABASE_URL"` | Environment variable for database URL |
| `ENV_BACKUP_DIR` | `"PASSWAULT_BACKUP_DIR"` | Environment variable for backup directory |

##### `get_database_url() -> str` (classmethod)

Get database URL from environment or default to SQLite.

**Returns:** Database URL string. Defaults to `sqlite:///<data_dir>/passwault.db`.

##### `get_database_type() -> DatabaseType` (classmethod)

Determine database type from the configured URL.

**Returns:** `DatabaseType.SQLITE` or `DatabaseType.POSTGRESQL`.

**Raises:** `ValueError` if URL scheme is not supported.

##### `get_backup_dir() -> Path` (classmethod)

Get backup directory from environment or default. In portable mode, backups go into the portable data directory.

**Returns:** `Path` to the backup directory (created if absent).

##### `is_postgresql() -> bool` (classmethod)

Check if using PostgreSQL backend.

##### `is_sqlite() -> bool` (classmethod)

Check if using SQLite backend.

---

## Database Models

### `passwault/core/database/models.py`

SQLAlchemy ORM models for users and password entries.

#### `Base`

SQLAlchemy declarative base (`declarative_base()`).

#### `class User(Base)`

User model for authentication and encryption key management.

**Table:** `users`

| Column | Type | Constraints | Default |
|--------|------|-------------|---------|
| `id` | `Integer` | Primary key, autoincrement | — |
| `username` | `String(100)` | Unique, not null, indexed | — |
| `email` | `String(255)` | Unique, nullable | — |
| `master_password_hash` | `LargeBinary` | Not null | — |
| `salt` | `LargeBinary` | Not null | — |
| `kdf_algorithm` | `String(50)` | Not null | `"PBKDF2"` |
| `kdf_iterations` | `Integer` | Not null | `600000` |
| `created_at` | `DateTime(timezone=True)` | Not null | `func.now()` |
| `updated_at` | `DateTime(timezone=True)` | Not null | `func.now()` (auto-update) |
| `last_login` | `DateTime(timezone=True)` | Nullable | — |

**Relationships:** `passwords` — one-to-many to `PasswordManager` (cascade delete).

#### `class PasswordManager(Base)`

Password entry model for storing encrypted passwords.

**Table:** `password_manager`

| Column | Type | Constraints | Default |
|--------|------|-------------|---------|
| `id` | `Integer` | Primary key, autoincrement | — |
| `user_id` | `Integer` | FK → `users.id` (cascade delete), not null | — |
| `resource_name` | `String(100)` | Not null | — |
| `username` | `String(255)` | Nullable | — |
| `encrypted_password` | `LargeBinary` | Not null | — |
| `nonce` | `LargeBinary` | Not null | — |
| `website` | `String(255)` | Nullable | — |
| `description` | `Text` | Nullable | — |
| `tags` | `String(255)` | Nullable | — |
| `created_at` | `DateTime(timezone=True)` | Not null | `func.now()` |
| `updated_at` | `DateTime(timezone=True)` | Not null | `func.now()` (auto-update) |

**Constraints:**
- `UniqueConstraint("user_id", "resource_name", name="uix_user_resource")`
- `Index("idx_user_passwords", "user_id")`
- `Index("idx_resource_name", "user_id", "resource_name")`

**Relationships:** `user` — many-to-one to `User`.

#### `create_db_engine() -> Engine`

Create database engine based on configuration. For SQLite, enables `PRAGMA foreign_keys=ON` via event listener.

#### `get_session_factory(db_engine=None) -> sessionmaker`

Get session factory for the given engine. Creates a new engine if `db_engine` is `None`.

#### Module-level instances

| Name | Type | Description |
|------|------|-------------|
| `engine` | `Engine` | Module-level database engine |
| `SessionLocal` | `sessionmaker` | Module-level session factory |

---

## Repositories

### UserRepository

#### `passwault/core/database/user_repository.py`

Repository for user management and authentication.

#### `class UserRepository`

Handles user registration, authentication, and related operations. Uses `CryptoService` for password hashing and key derivation.

##### `__init__(self) -> None`

Initializes with a `CryptoService` instance.

##### `register(self, username: str, master_password: str, email: Optional[str] = None) -> int`

Register a new user account. Creates a bcrypt-hashed master password, a random PBKDF2 salt, and stores default KDF parameters.

**Returns:** User ID of the new user.

**Raises:**
- `ResourceExistsError` — username or email already exists
- `DatabaseError` — database operation failed

##### `authenticate(self, username: str, master_password: str) -> Dict[str, Any]`

Authenticate a user and derive their encryption key.

**Returns:** Dict with keys:
| Key | Type | Description |
|-----|------|-------------|
| `user_id` | `int` | User ID |
| `username` | `str` | Username |
| `encryption_key` | `bytes` | 32-byte AES-256 key |
| `salt` | `bytes` | PBKDF2 salt |
| `kdf_iterations` | `int` | PBKDF2 iteration count |

**Raises:**
- `AuthenticationError` — user not found or invalid password
- `DatabaseError` — database operation failed

##### `get_user_by_id(self, user_id: int) -> Dict[str, Any]`

Get user info by ID.

**Returns:** Dict with `user_id`, `username`, `email`, `created_at`, `last_login`.

**Raises:** `ResourceNotFoundError`, `DatabaseError`

##### `get_user_by_username(self, username: str) -> Dict[str, Any]`

Get user info by username.

**Returns:** Dict with `user_id`, `username`, `email`, `created_at`, `last_login`.

**Raises:** `ResourceNotFoundError`, `DatabaseError`

##### `check_username_exists(self, username: str) -> bool`

Check if a username already exists.

**Raises:** `DatabaseError`

---

### PasswordRepository

#### `passwault/core/database/password_manager.py`

Repository for encrypted password storage and retrieval. All passwords are encrypted using AES-256-GCM before storage.

#### `class PasswordRepository`

All passwords are encrypted with AES-256-GCM before storage. Each user's passwords are isolated and can only be accessed with their encryption key.

##### `__init__(self) -> None`

Initializes with a `CryptoService` instance.

##### `save_password(self, user_id: int, encryption_key: bytes, resource_name: str, password: str, username: Optional[str] = None, website: Optional[str] = None, description: Optional[str] = None, tags: Optional[str] = None) -> int`

Save a new password entry with encryption. Each user can have only one password per `resource_name`.

**Returns:** Password entry ID.

**Raises:** `ResourceExistsError`, `DatabaseError`

##### `get_password_by_resource_name(self, user_id: int, encryption_key: bytes, resource_name: str) -> Dict[str, Any]`

Retrieve and decrypt a password by resource name.

**Returns:** Dict with keys: `id`, `resource_name`, `username`, `password` (decrypted), `website`, `description`, `tags`, `created_at`, `updated_at`.

**Raises:** `ResourceNotFoundError`, `EncryptionError`, `DatabaseError`

##### `get_password_by_username(self, user_id: int, encryption_key: bytes, username: str) -> List[Dict[str, Any]]`

Retrieve and decrypt passwords by associated username. Multiple entries may share the same username.

**Returns:** List of password data dicts. Entries that cannot be decrypted are skipped.

**Raises:** `ResourceNotFoundError`, `EncryptionError`, `DatabaseError`

##### `get_all_passwords(self, user_id: int, encryption_key: bytes) -> List[Dict[str, Any]]`

Retrieve and decrypt all passwords for a user.

**Returns:** List of password data dicts (may be empty).

**Raises:** `EncryptionError` (if entries exist but none could be decrypted), `DatabaseError`

##### `update_password(self, user_id: int, encryption_key: bytes, resource_name: str, new_password: str, username: Optional[str] = None, website: Optional[str] = None, description: Optional[str] = None, tags: Optional[str] = None) -> None`

Update an existing password entry. Only updates optional fields that are not `None`.

**Raises:** `ResourceNotFoundError`, `DatabaseError`

##### `delete_password(self, user_id: int, resource_name: str) -> None`

Delete a password entry.

**Raises:** `ResourceNotFoundError`, `DatabaseError`

##### `check_resource_exists(self, user_id: int, resource_name: str) -> bool`

Check if a password exists for a resource.

**Raises:** `DatabaseError`

---

## Services

### CryptoService

#### `passwault/core/services/crypto_service.py`

Cryptography service for password encryption and key management.

#### `class CryptoService`

Provides all cryptographic operations: master password hashing (bcrypt), encryption key derivation (PBKDF2-HMAC-SHA256), and password encryption/decryption (AES-256-GCM).

**Class constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_KDF_ITERATIONS` | `600000` | OWASP 2023 recommendation |
| `DEFAULT_SALT_LENGTH` | `32` | 256-bit salt |
| `DEFAULT_NONCE_LENGTH` | `12` | 96-bit GCM nonce |

##### `generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes` (static)

Generate a cryptographically secure random salt using `os.urandom()`.

##### `hash_master_password(password: str) -> bytes` (static)

Hash a master password using bcrypt with automatic salt generation and cost factor.

**Returns:** bcrypt hash as bytes (includes salt and parameters).

##### `verify_master_password(password: str, password_hash: bytes) -> bool` (static)

Verify a master password against a bcrypt hash. Uses constant-time comparison to prevent timing attacks.

**Returns:** `True` if password matches, `False` otherwise.

##### `derive_encryption_key(master_password: str, salt: bytes, iterations: int = DEFAULT_KDF_ITERATIONS) -> bytes` (static)

Derive a 32-byte encryption key from a master password using PBKDF2-HMAC-SHA256.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_password` | `str` | User's master password |
| `salt` | `bytes` | Random salt (stored per user) |
| `iterations` | `int` | PBKDF2 iteration count (default: 600,000) |

**Returns:** 32-byte (256-bit) key suitable for AES-256.

##### `encrypt_password(plaintext: str, encryption_key: bytes) -> Tuple[bytes, bytes]` (static)

Encrypt a password using AES-256-GCM.

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `str` | Password to encrypt |
| `encryption_key` | `bytes` | 32-byte AES-256 key |

**Returns:** `(ciphertext, nonce)` — nonce is 12 bytes and must be stored alongside the ciphertext.

**Raises:** `ValueError` if `encryption_key` is not 32 bytes.

##### `decrypt_password(ciphertext: bytes, nonce: bytes, encryption_key: bytes) -> str` (static)

Decrypt a password using AES-256-GCM. Verifies the authentication tag to ensure data integrity.

**Returns:** Decrypted password as `str`.

**Raises:**
- `ValueError` — key is not 32 bytes
- `cryptography.exceptions.InvalidTag` — authentication failed (data tampered or wrong key)

---

### BackupService

#### `passwault/core/services/backup_service.py`

Backup service for database backup and restore operations. Supports both SQLite (file copy) and PostgreSQL (`pg_dump`).

#### `class BackupService`

##### `__init__(self, backup_dir: Optional[Path] = None) -> None`

Initialize backup service.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `backup_dir` | `Path \| None` | `None` | Custom backup directory (defaults to `Config.get_backup_dir()`) |

##### `create_backup(self, compress: bool = True) -> Path`

Create a database backup.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `compress` | `bool` | `True` | Whether to gzip-compress the backup |

**Returns:** `Path` to the created backup file.

**Raises:** `RuntimeError` if backup fails.

**Backup formats:**
| Backend | Compressed | Uncompressed |
|---------|-----------|-------------|
| SQLite | `passwault_<timestamp>.db.gz` | `passwault_<timestamp>.db` |
| PostgreSQL | `passwault_<timestamp>.sql.gz` | `passwault_<timestamp>.sql` |

##### `list_backups(self) -> List[Path]`

List all available backups, sorted by modification time (newest first).

##### `restore_backup(self, backup_path: Path) -> None`

Restore database from a backup file. Infers backup type from the file extension. For SQLite, creates a `.bak` copy of the current database before restoring.

**Raises:**
- `RuntimeError` — file not found or restore failed
- `ValueError` — backup type doesn't match current database backend

##### `cleanup_old_backups(self, retention_days: int = 30) -> int`

Remove backups older than the retention period.

**Returns:** Number of backups removed.

---

### MigrationService

#### `passwault/core/services/migration_service.py`

Migration service for exporting data to a portable SQLite database. Copies all users and encrypted passwords from the source database to a new SQLite file. Encrypted data is copied as-is — no decryption needed.

#### `class MigrationService`

##### `migrate_to_sqlite(self, output_path: str) -> Path`

Migrate all data from the current database to a SQLite file.

| Parameter | Type | Description |
|-----------|------|-------------|
| `output_path` | `str` | Destination path for the SQLite file |

**Returns:** `Path` to the created SQLite file.

**Raises:**
- `FileExistsError` — output file already exists
- `RuntimeError` — migration failed (partial file is cleaned up)

The migration preserves all fields including user IDs, encrypted passwords, nonces, and timestamps.

---

## Commands

### Authentication Commands

#### `passwault/core/commands/authenticator.py`

Authentication commands for user registration, login, and logout.

##### `register(username: str, password: Optional[str], email: Optional[str], session_manager: SessionManager) -> None`

Register a new user account. Prompts for password (with masking and confirmation) if not provided.

##### `login(username: str, password: Optional[str], session_manager: SessionManager) -> None`

Authenticate user and create session. Verifies credentials and creates an authenticated session with encryption key caching.

##### `logout(session_manager: SessionManager) -> None`

Log out current user and clear session. Removes encryption keys from memory and deletes the session file from disk.

##### `change_master_password(old_password: Optional[str], new_password: Optional[str], session_manager: SessionManager) -> None`

Change the user's master password and re-encrypt all passwords. Decorated with `@require_auth`.

Performs the following in a single database transaction:
1. Verifies the old password
2. Generates a new salt and derives a new encryption key
3. Re-encrypts every stored password with the new key
4. Updates the user's password hash, salt, and KDF parameters
5. Updates the session with the new encryption key

---

### Password Commands

#### `passwault/core/commands/password.py`

Password management commands with encryption and authentication.

##### `add_password(resource_name: str, password: str, session_manager: SessionManager, username: Optional[str] = None, website: Optional[str] = None, description: Optional[str] = None, tags: Optional[str] = None) -> None`

Save a new encrypted password entry. Decorated with `@require_auth`.

##### `get_password(session_manager: SessionManager, resource_name: Optional[str] = None, username: Optional[str] = None, all_passwords: bool = False) -> None`

Load and decrypt password(s). Dispatches to the appropriate repository method based on which parameter is provided. Decorated with `@require_auth`.

##### `update_password(resource_name: str, new_password: str, session_manager: SessionManager, username: Optional[str] = None, website: Optional[str] = None, description: Optional[str] = None, tags: Optional[str] = None) -> None`

Update an existing password entry. Decorated with `@require_auth`.

##### `delete_password(resource_name: str, session_manager: SessionManager) -> None`

Delete a password entry permanently. Decorated with `@require_auth`.

##### `generate_password(password_length: int = 15, has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True) -> Optional[str]`

Generate a random secure password. Does **not** require authentication.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password_length` | `int` | `15` | Length of the generated password |
| `has_symbols` | `bool` | `True` | Include symbols (`!`, `#`, `$`, `%`, `&`) |
| `has_digits` | `bool` | `True` | Include digits |
| `has_uppercase` | `bool` | `True` | Include uppercase letters |

**Returns:** Generated password string, or `None` if generation fails after 10 retries.

Character pool: lowercase letters, plus optional symbols, digits, and uppercase. Validates that the generated password contains at least one character from each enabled class.

##### `generate_and_save(session_manager: SessionManager, password_length: int = 15, has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True) -> None`

Interactive password generation with save option. Decorated with `@require_auth`.

Enters an interactive loop:
- **r** — regenerate password
- **s** — save to database (prompts for resource name and metadata)
- **q** — quit without saving

After saving, attempts to copy the password to the clipboard.

---

## Utilities

### SessionManager

#### `passwault/core/utils/session_manager.py`

Session management for user authentication and encryption key caching.

#### `class SessionManager`

Manages user sessions and encryption key caching. Session data is encrypted on disk using Fernet symmetric encryption.

**Class constant:** `SESSION_TIMEOUT_MINUTES = 10`

##### `__init__(self, session_file: str = ".session") -> None`

Initialize session manager. Sets up file paths in the data directory and loads any existing session from disk.

| File | Path | Purpose |
|------|------|---------|
| Session file | `<data_dir>/.session` | Fernet-encrypted session data |
| Key file | `<data_dir>/.enckey` | Fernet encryption key |

##### `is_logged_in(self) -> bool`

Check if there is an active, non-expired session.

##### `create_session(self, user_data: Dict[str, Any]) -> None`

Create a new user session. Caches the encryption key in memory and saves session data (Fernet-encrypted) to disk.

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_data` | `dict` | Must contain `user_id`, `username`, `encryption_key` |

##### `get_encryption_key(self) -> Optional[bytes]`

Retrieve the cached encryption key from memory. Returns `None` if not logged in.

##### `get_user_id(self) -> Optional[int]`

Get the current user's ID, or `None`.

##### `get_username(self) -> Optional[str]`

Get the current user's username, or `None`.

##### `get_session(self) -> Optional[Dict[str, Any]]`

Get the raw session dict (without encryption key).

##### `logout(self) -> None`

Clear session. Removes encryption key from memory, sets session to `None`, and deletes the session file and key file from disk.

##### `expire_session(self) -> None`

Check and expire session if timeout exceeded. Sessions expire after `SESSION_TIMEOUT_MINUTES` (10) minutes of inactivity.

---

### Decorators

#### `passwault/core/utils/decorators.py`

Authentication decorators for protecting password operations.

##### `require_auth(func: Callable) -> Callable`

Decorator to require active authentication before executing a function.

Checks:
1. The decorated function receives a `SessionManager` instance (as a keyword argument `session_manager` or by scanning positional arguments)
2. The user has an active session (`is_logged_in()`)
3. An encryption key is available in memory (`get_encryption_key()`)

If any check fails, logs an error and returns `None` without calling the wrapped function.

**Used by:** `add_password`, `get_password`, `update_password`, `delete_password`, `generate_and_save`, `change_master_password`, `Embedder.encode`, `Embedder.decode`

---

### Custom Exceptions

#### `passwault/core/utils/local_types.py`

Custom exception hierarchy for Passwault.

```
Exception
  └── PasswaultError             Base exception for all Passwault errors
        ├── AuthenticationError   Authentication failed
        ├── DatabaseError         Database operation failed
        ├── EncryptionError       Encryption/decryption operation failed
        ├── ResourceNotFoundError Requested resource not found
        ├── ResourceExistsError   Resource already exists
        └── ClipboardError        Clipboard operation failed
```

---

### Logger

#### `passwault/core/utils/logger.py`

Colored console logging.

#### `class Colors(Enum)`

| Value | ANSI code |
|-------|-----------|
| `RESET` | `\033[0m` |
| `RED` | `\033[31m` |
| `GREEN` | `\033[32m` |
| `YELLOW` | `\033[33m` |

#### `class Logger`

All methods are `@staticmethod`. Output format: `[LEVEL] YYYY-MM-DD HH:MM:SS - message`.

##### `info(message: str) -> None`

Print an info message in green.

##### `error(message: str) -> None`

Print an error message in red.

##### `debug(message: str) -> None`

Print a debug message in yellow.

##### `warn(message: str) -> None`

Print a warning message in yellow.

---

### Data Directory

#### `passwault/core/utils/data_dir.py`

Application data directory management with portable mode support.

##### `set_portable_data_dir(exe_dir: Path) -> None`

Set the data directory to a portable path relative to the executable. Sets the directory to `<exe_dir>/passwault-data/` and creates it.

##### `get_data_dir() -> Path`

Get the application data directory, creating it if needed.

| Mode | Path |
|------|------|
| Portable | `<executable_dir>/passwault-data/` |
| Normal | `~/.local/share/passwault/` |

##### `get_executable_dir() -> Path`

Get the directory containing the running executable or script.

| Context | Resolution |
|---------|-----------|
| PyInstaller bundle (`sys.frozen`) | `Path(sys.executable).parent` |
| Normal Python | `Path(__file__).resolve().parent.parent.parent.parent` |

---

### Clipboard

#### `passwault/core/utils/clipboard.py`

Cross-platform clipboard utilities.

##### `copy_to_clipboard(text: str) -> bool`

Copy text to the system clipboard using the platform-appropriate tool.

| Platform | Tool | Encoding |
|----------|------|----------|
| WSL | `clip.exe` | UTF-16-LE |
| macOS | `pbcopy` | UTF-8 |
| Linux (X11) | `xclip -selection clipboard` or `xsel --clipboard --input` | UTF-8 |
| Windows | `clip` | UTF-16-LE |

**Returns:** `True` if successful, `False` if no clipboard tool available.

**Raises:** `ClipboardError` if the clipboard command fails.

##### `try_copy_to_clipboard(text: str) -> bool`

Non-blocking wrapper around `copy_to_clipboard()`. Logs success or failure instead of raising exceptions.

**Returns:** `True` if successful, `False` otherwise.

---

### File Handler

#### `passwault/core/utils/file_handler.py`

File validation and reading utilities.

**Module constants:**
| Constant | Value |
|----------|-------|
| `ALLOWED_EXT` | `[".csv", ".json"]` |
| `VALID_IMAGE_EXTENSIONS` | `[".jpg", ".png", ".gif", ".jpeg", ".tiff", ".bmp"]` |

##### `valid_image_file(file: str) -> str`

Validate that a file exists and has a valid image extension. Used as an argparse `type=` validator for the `imagepass` command.

**Raises:** `argparse.ArgumentTypeError` on failure.

##### `valid_file(file: str) -> str`

Validate that a file exists and has a `.csv` or `.json` extension.

**Raises:** `argparse.ArgumentTypeError` on failure.

##### `read_file(file: str) -> Tuple[Tuple[str, str]] | None`

Read and parse a CSV or JSON file. Dispatches based on file extension.

---

### Password Masking

#### `passwault/core/utils/password.py`

##### `get_password_with_mask() -> str`

Prompt for a password with input masking. Uses `termios`/`tty` to set raw terminal mode, displaying `*` for each character typed. Handles backspace.

**Returns:** The entered password string.

---

## Imagepass

### Embedder

#### `passwault/imagepass/embedder.py`

LSB steganography encoder/decoder for hiding passwords in images.

#### `class Embedder`

##### `__init__(self, image_path: Union[Path, str], output_dir: Optional[Union[Path, str]] = None) -> None`

Initialize with an image path and optional output directory.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `image_path` | `Path \| str` | — | Path to the image file |
| `output_dir` | `Path \| str \| None` | `None` | Output directory for encoded images |

##### `encode(self, message: str, session_manager: SessionManager) -> str`

Encode a message into an image using LSB steganography. Decorated with `@require_auth`.

1. Checks image capacity (pixels x channels)
2. Selects a random band for single-band embedding
3. Generates a random spacing key
4. Creates a 24-byte header (marker, band mask, message length, algorithm ID, key, CRC32)
5. Embeds header + payload (message bytes + CRC32) into the LSBs of pixel values
6. Saves the modified image

**Returns:** Path to the saved image.

**Raises:** `NotImplementedError` if multi-band embedding is needed (message too large for a single channel).

##### `decode(self, session_manager: SessionManager) -> Optional[str]`

Decode a hidden message from an image. Decorated with `@require_auth`.

Iterates over all image bands, checks for a valid header (magic marker `0xDEADCAFE`), extracts the message, and verifies its CRC32 integrity.

**Returns:** Decoded message string, or `None` if no valid embedded message is found.

---

### ImageHandler

#### `passwault/imagepass/utils/image_handler.py`

Image I/O and pixel manipulation using Pillow.

#### `class ImageHandler`

##### `__init__(self, image_path: Path, output_dir: Optional[Path] = None) -> None`

Open and load an image. Computes dimensions, available bands, and total pixel count.

| Attribute | Type | Description |
|-----------|------|-------------|
| `width` | `int` | Image width in pixels |
| `height` | `int` | Image height in pixels |
| `bands` | `dict[str, int]` | Map of band name to index (e.g., `{"R": 0, "G": 1, "B": 2}`) |
| `size` | `int` | Total pixel count (`width * height`) |

##### `get_band_values(self, band: str) -> List[int]`

Get all pixel values for a specific color channel.

**Raises:** `ValueError` if band is not in the image.

##### `replace_band(self, band: str, band_values: List[int]) -> Image.Image`

Replace a color channel with modified pixel values and return the new image.

**Raises:**
- `ValueError` — invalid band
- `TypeError` — image is JPEG (lossy format not supported)

##### `save_image_to_file(self, image: Image.Image) -> str`

Save the image to the output directory.

**Returns:** Path to the saved file as a string.

---

### Imagepass Config & Struct

#### `passwault/imagepass/config.py`

| Constant | Value | Description |
|----------|-------|-------------|
| `MARKER` | `0xDEADCAFE` | 4-byte magic marker for header validation |
| `HEADER_LEN` | `24` | Total header length in bytes (20 fixed + 4 CRC) |
| `BYTE_SIZE` | `8` | Bits per byte |

#### `passwault/imagepass/struct.py`

##### `@dataclass class Header`

Binary header for steganography data.

| Field | Size | Description |
|-------|------|-------------|
| `marker` | 4 bytes | Magic marker (`0xDEADCAFE`) |
| `band_mask` | 1 byte | Bitmask for R/G/B/A/L channels |
| `message_len` | 4 bytes | Message length in bytes |
| `algo_id` | 1 byte | Algorithm ID (currently `1`) |
| `key` | 10 bytes | Steganography spacing key |

**Total:** 20 bytes + 4 bytes CRC32 = 24 bytes. Packed with `struct.pack(">IBIB10s", ...)` (big-endian).

#### `passwault/imagepass/utils/utils.py`

##### `key_generator(length: int = 10, has_symbols: bool = True, has_digits: bool = True, has_uppercase: bool = True) -> str`

Generate a random key string using `secrets.choice` for cryptographic randomness. The key controls variable pixel-spacing during LSB encoding/decoding.
