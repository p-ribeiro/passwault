# Passwault

[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/p-ribeiro/passwault/actions/workflows/python-package.yml/badge.svg)](https://github.com/p-ribeiro/passwault/actions/workflows/python-package.yml)
[![CodeQL](https://github.com/p-ribeiro/passwault/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/p-ribeiro/passwault/actions/workflows/github-code-scanning/codeql)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure, local-first password manager with military-grade encryption and image steganography capabilities.

## 🔐 Overview

Passwault is a command-line password manager that prioritizes security and privacy. All passwords are encrypted with AES-256-GCM before being stored locally, and your master password never leaves your machine. The unique image steganography feature allows you to hide passwords in plain sight by encoding them into image files.

### Key Features

- **🔒 Military-Grade Encryption**: AES-256-GCM encryption with PBKDF2 key derivation (600,000 iterations)
- **👤 Multi-User Support**: Separate encrypted vaults for multiple users with data isolation
- **🎨 Image Steganography**: Hide passwords in images using LSB (Least Significant Bit) encoding
- **⚡ Session Management**: Secure sessions with automatic timeout (10 minutes)
- **🔑 Zero-Knowledge Architecture**: Master password and encryption keys never persisted to disk
- **🛡️ Authenticated Encryption**: AES-GCM provides both confidentiality and authenticity
- **🔐 Password Generation**: Cryptographically secure random password generation
- **📦 Local Storage**: SQLite database - no cloud, no third parties
- **💾 Portable USB Mode**: Run from a USB drive with PyInstaller — no installation needed

## 🚀 Quick Start

### Installation

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd passwault-project
   ```

2. **Install dependencies** with uv:
   ```bash
   uv sync

   # Install the package in editable mode
   uv pip install -e .
   ```

3. **Verify installation**:
   ```bash
   uv run passwault --help
   ```

   You should see the help menu with all available commands.

4. **Optional: Install clipboard tool** (for auto-copy feature):
   ```bash
   # Linux (X11)
   sudo apt install xclip
   # or
   sudo apt install xsel

   # macOS - pbcopy is pre-installed

   # WSL2 - clip.exe works if Windows interop is enabled
   # Otherwise install xclip/xsel as above
   ```

### First-Time Setup

1. **Register a new account**:
   ```bash
   uv run passwault auth register -u yourname
   # You'll be prompted for a master password
   ```

2. **Login to your account**:
   ```bash
   uv run passwault auth login -u yourname
   # Enter your master password when prompted
   ```

3. **Add your first password**:
   ```bash
   uv run passwault add -n github -p "your_github_password" -u "your_username"
   ```

4. **Retrieve your password**:
   ```bash
   uv run passwault get -n github
   ```

## 🗄️ Database Configuration

By default, Passwault uses SQLite and stores data in `~/.passwault/`. For advanced users, PostgreSQL is also supported.

### Configuration Priority

Passwault loads database configuration in this order:

1. **Environment variable** (highest priority): `DATABASE_URL`
2. **Config file**: `~/.config/passwault/.env`
3. **Default**: SQLite at `~/.passwault/passwault.db`

### Using PostgreSQL

#### Option 1: Environment Variable

```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/passwault"
passwault auth login -u yourname
```

#### Option 2: Config File

Create a config file at `~/.config/passwault/.env`:

```bash
mkdir -p ~/.config/passwault
echo 'DATABASE_URL="postgresql://user:password@localhost:5432/passwault"' > ~/.config/passwault/.env
```

This is the recommended approach when installing passwault as a uv tool:

```bash
uv tool install passwault
passwault auth login -u yourname  # Uses config from ~/.config/passwault/.env
```

### Default SQLite (No Configuration Needed)

If no `DATABASE_URL` is set, Passwault automatically uses SQLite:

```bash
passwault auth register -u yourname  # Data stored in ~/.passwault/passwault.db
```

## 💾 Portable USB Mode

Passwault can run entirely from a USB drive with no installation required. Data is stored alongside the executable, so your passwords travel with you.

### Building the Portable Executable

```bash
# Install dev dependencies (includes PyInstaller)
uv sync --dev

# Build the portable bundle
make build-portable
```

This creates a `dist/passwault/` folder containing the executable and launcher scripts. Copy the entire folder to your USB drive.

### Running from USB

Use the included launcher scripts from the USB drive:

```bash
# Linux / macOS
./run.sh auth login -u yourname

# Windows
run.bat auth login -u yourname
```

The `--portable` flag (added automatically by the launchers) tells Passwault to store all data in a `passwault-data/` directory next to the executable instead of `~/.local/share/passwault/`.

### Migrating Existing Data to USB

If you already have passwords stored in a local or PostgreSQL database, use the `migrate` command to export them to a portable SQLite file:

```bash
passwault migrate --to-sqlite -o /mnt/usb/passwault/passwault-data/passwault.db
```

Encrypted passwords and nonces are copied as-is — no login or decryption is needed. The output file must not already exist (safety guard).

## 📚 Complete Command Reference

### Authentication Commands

#### Register a New User
```bash
passwault auth register -u <username> [-p <password>] [-e <email>]

# Example
passwault auth register -u john -e john@example.com
# Password will be prompted securely if not provided
```

#### Login
```bash
passwault auth login -u <username> [-p <password>]

# Example
passwault auth login -u john
# Password will be prompted securely if not provided
```

#### Logout
```bash
passwault auth logout
```

#### Change Master Password
```bash
passwault auth change-password [-o <old-password>] [-n <new-password>]

# Example (will prompt for passwords)
passwault auth change-password
```
**Note**: This command re-encrypts all your stored passwords with the new encryption key derived from your new master password.

### Password Management

#### Add a Password
```bash
passwault add -n <resource-name> -p <password> [options]

Options:
  -u, --username        Username associated with this password
  -w, --website         Website URL
  -d, --description     Description
  -t, --tags            Comma-separated tags

# Examples
passwault add -n github -p "mypassword123" -u "john"
passwault add -n aws -p "complex_pass" -w "https://aws.amazon.com" -t "cloud,work"
```

#### Get a Password
```bash
# Get by resource name
passwault get -n <resource-name>

# Get all passwords for a username
passwault get -u <username>

# Get all passwords
passwault get -a

# Examples
passwault get -n github
passwault get -u john
passwault get -a
```

#### Update a Password
```bash
passwault update -n <resource-name> -p <new-password> [options]

# Example
passwault update -n github -p "new_password456" -w "https://github.com"
```

#### Delete a Password
```bash
passwault delete -n <resource-name>

# Example
passwault delete -n old_account
```

### Password Generation

Generate a cryptographically secure random password:

```bash
passwault generate [options]

Options:
  -l, --length          Password length (default: 16)
  --no-symbols          Exclude symbols
  --no-digits           Exclude digits
  --no-uppercase        Exclude uppercase letters

# Examples
passwault generate
passwault generate -l 32
passwault generate -l 20 --no-symbols
```

### Image Steganography (Imagepass)

Hide passwords inside images using LSB (Least Significant Bit) steganography.

#### Encode (Hide Password in Image)
```bash
passwault imagepass encode <image_path> -p <password>

# Example
passwault imagepass encode photo.png -p "my_secret_password"
# Creates: results/photo.png with hidden password
```

#### Decode (Extract Password from Image)
```bash
passwault imagepass decode <image_path>

# Example
passwault imagepass decode results/photo.png
# Output: my_secret_password
```

**Supported Image Formats**: PNG, BMP (lossless formats only - JPEG compression will destroy hidden data)

### Database Migration

Export your database to a portable SQLite file:

```bash
passwault migrate --to-sqlite -o <output-path>

# Example: export to a USB drive
passwault migrate --to-sqlite -o /mnt/usb/passwault-data/passwault.db
```

## 🔒 Security Architecture

### Encryption Flow

```
Master Password (user input)
    ├─→ bcrypt hash → stored in users.master_password_hash (authentication)
    └─→ PBKDF2-SHA256 + salt → encryption_key (in-memory only)
             └─→ AES-256-GCM → encrypted_password + nonce (stored in DB)
```

### Security Features

1. **Master Password Protection**
   - Never stored (only bcrypt hash)
   - Verified using constant-time comparison
   - High bcrypt cost factor (12) prevents brute force

2. **Encryption Key Derivation**
   - PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
   - Unique 32-byte salt per user
   - Encryption key exists only in memory during active session

3. **Password Encryption**
   - AES-256-GCM (authenticated encryption)
   - Unique nonce per password entry
   - Tamper detection via GCM authentication tag

4. **Session Security**
   - 10-minute automatic timeout
   - Encryption keys cleared on logout/timeout
   - Session file encrypted (does not contain encryption key)

5. **Multi-User Isolation**
   - Each user has unique salt and encryption key
   - Foreign key constraints enforce data isolation
   - No cross-user password access

### Threat Model

**Protected Against:**
- ✅ Database theft (passwords encrypted with user-specific keys)
- ✅ SQL injection (SQLAlchemy ORM parameterization)
- ✅ Timing attacks (bcrypt constant-time comparison)
- ✅ Brute force attacks (high KDF iterations)
- ✅ Password tampering (GCM authentication)
- ✅ Session hijacking (encrypted session files)

**Not Protected Against:**
- ❌ Keyloggers on compromised systems
- ❌ Memory dumps while session is active
- ❌ Physical access to unlocked system
- ❌ Master password compromise (use a strong master password!)

## 📁 Project Structure

```
passwault/
├── core/
│   ├── commands/           # CLI command implementations
│   │   ├── authenticator.py    # Register, login, logout, change password
│   │   └── password.py         # Add, get, update, delete, generate
│   ├── database/           # Data layer
│   │   ├── models.py           # SQLAlchemy models (User, PasswordManager)
│   │   ├── user_repository.py  # User CRUD operations
│   │   └── password_manager.py # Password CRUD operations
│   ├── services/           # Business logic
│   │   └── crypto_service.py   # Cryptography operations
│   ├── utils/              # Utilities
│   │   ├── decorators.py       # @require_auth decorator
│   │   ├── session_manager.py  # Session handling
│   │   ├── local_types.py      # Custom exception classes
│   │   └── logger.py           # Logging utilities
│   └── cli.py              # Argument parser
├── imagepass/              # Steganography module
│   ├── embedder.py             # LSB encoding/decoding
│   └── utils/
│       └── image_handler.py    # Image manipulation
└── tests/                  # Comprehensive test suite
```

## 🧪 Testing

Passwault includes a comprehensive test suite with 247 tests covering:
- Authentication flows
- Encryption/decryption
- Password operations
- Session management
- Multi-user isolation
- Image steganography
- Error handling

Run the test suite:

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage report
uv run pytest tests/ --cov=passwault --cov-report=html

# Run specific test suite
uv run pytest tests/test_authenticator.py -v
uv run pytest tests/test_crypto_service.py -v
uv run pytest tests/imagepass/ -v
```

## 🛠️ Development

### Code Quality

The project uses modern Python tooling:
- **Linting**: flake8 (max line length: 100)
- **Formatting**: black
- **Type Hints**: Throughout codebase
- **Testing**: pytest with high coverage

Run code quality checks:

```bash
# Format code
uv run black passwault tests

# Lint code
uv run flake8 passwault tests --max-line-length=100

# Run tests
uv run pytest tests/ -v
```

### Architecture Patterns

- **Repository Pattern**: Clean separation between data access and business logic
- **Decorator Pattern**: `@require_auth` for authentication enforcement
- **Custom Exceptions**: Typed exception hierarchy for clear error handling
- **Dependency Injection**: Session managers and services passed explicitly

## 🔮 Future Enhancements

### Planned Features (Phase 9+)

1. **REST API Backend**
   - Convert to client-server architecture
   - JWT-based API authentication
   - Zero-knowledge design (server never sees decrypted passwords)
   - Keep client-side encryption

2. **Enhanced CLI**
   - Interactive TUI (Terminal User Interface)
   - Password search and filtering
   - Password strength analysis
   - Import/export functionality

3. **Additional Security**
   - 2FA/TOTP support
   - Hardware key (YubiKey) integration
   - Password breach checking (Have I Been Pwned API)
   - Secure password sharing

4. **Cloud Sync**
   - Optional encrypted cloud backup
   - End-to-end encryption
   - Multi-device synchronization

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`uv run pytest tests/`)
5. Follow code style (black + flake8)
6. Submit a pull request

## 📝 License

This project is open source. Please check the LICENSE file for details.

## ⚠️ Security Disclaimer

While Passwault uses industry-standard cryptography (AES-256-GCM, PBKDF2, bcrypt), it has not undergone a professional security audit. Use at your own risk. For critical passwords, consider using established password managers like Bitwarden or 1Password.

**Important**:
- Never forget your master password (it cannot be recovered)
- Use a strong, unique master password
- Keep your system secure (antivirus, firewall, updates)
- Regular backups recommended (encrypted database is in `~/.passwault/`)

## 🆘 Support

For issues, questions, or feature requests:
1. Check the [documentation](#-complete-command-reference)
2. Search existing issues on GitHub
3. Open a new issue with details

## 🎯 Why Passwault?

**Zero Trust**: Your master password and encryption keys never leave your machine. No cloud, no third parties, complete control.

**Open Source**: Full transparency. Review the code, audit the cryptography, verify the security model.

**Educational**: Learn about modern cryptography, key derivation, authenticated encryption, and steganography through a real-world application.

**Unique Features**: Image steganography sets Passwault apart - hide passwords in plain sight for an additional layer of obfuscation.

---

Built with 🔒 and ❤️ for security-conscious users.
