# Passwault Password Manager Enhancement Plan

## Overview

Enhance the existing Passwault CLI password manager with secure authentication, encryption at rest, and multi-user support while preserving the unique image steganography feature.

## Current State

- **Language**: Python 3.14+
- **Database**: SQLite with SQLAlchemy ORM
- **Status**: Working CLI with basic commands (generate, save_password, load_password, imagepass)
- **Critical Issue**: Passwords stored as **plain text** in database (security vulnerability)
- **Missing**: User authentication system (code exists but commented out)
- **Strengths**: Image steganography module (imagepass) is functional and unique

## Goals

1. ✅ Implement user authentication (register/login/logout)
2. ✅ Add master password security for vault encryption
3. ✅ Encrypt all passwords at rest (AES-256-GCM)
4. ✅ Support multiple users with data isolation
5. ✅ Preserve image steganography functionality
6. ✅ Design for future REST API client-server architecture
7. ✅ No caching layer (direct database access for security)

---

## Architecture Design

### Encryption Flow

```
Master Password (user input)
    ├─→ bcrypt hash → stored in users.master_password_hash (authentication)
    └─→ PBKDF2-SHA256 + salt → encryption_key (in-memory only)
             └─→ AES-256-GCM → encrypted_password + nonce (stored)
```

### Database Schema Changes

**New Table: `users`**
```sql
- id (PK)
- username (unique)
- email
- master_password_hash (bcrypt)
- salt (32 bytes, for key derivation)
- kdf_algorithm, kdf_iterations
- created_at, updated_at, last_login
```

**Updated Table: `password_manager`**
```sql
+ user_id (FK to users.id)
- password (plain text) → encrypted_password (BLOB)
+ nonce (BLOB, for AES-GCM)
+ tags (VARCHAR, future filtering)
+ created_at, updated_at
+ UNIQUE(user_id, resource_name)
```

### Session Management

- **In-Memory**: encryption_key (cleared on logout/timeout)
- **On-Disk**: user_id, username, timestamp only
- **Timeout**: 10 minutes (existing configuration)
- **Security**: Never persist encryption key to disk

---

## Implementation Steps

### Phase 1: Database & Cryptography Foundation

#### 1.1 Update Database Models
**File**: `passwault/core/database/models.py`

- Create `User` model with authentication fields
- Update `PasswordManager` model:
  - Add `user_id` foreign key
  - Change `password` (String) → `encrypted_password` (BLOB)
  - Add `nonce` (BLOB) for AES-GCM
  - Add `tags`, `created_at`, `updated_at`
  - Add unique constraint on `(user_id, resource_name)`
  - Add indexes for performance

#### 1.2 Create Cryptography Service
**New File**: `passwault/core/services/crypto_service.py`

Implement `CryptoService` class with methods:
- `generate_salt()` - 32 random bytes
- `hash_master_password()` - bcrypt hashing
- `verify_master_password()` - bcrypt verification
- `derive_encryption_key()` - PBKDF2-HMAC-SHA256 (600k iterations)
- `encrypt_password()` - AES-256-GCM → (ciphertext, nonce)
- `decrypt_password()` - AES-256-GCM decryption

**Dependencies**: Already available (cryptography, bcrypt)

#### 1.3 Create User Repository
**File**: `passwault/core/database/user_repository.py`

Implement `UserRepository` class:
- `register(username, master_password, email)` - Create user with hashed password and salt
- `authenticate(username, master_password)` - Verify credentials, derive encryption key
- Handle duplicate username/email errors

### Phase 2: Session Management

#### 2.1 Update Session Manager
**File**: `passwault/core/utils/session_manager.py`

Modifications:
- Add `_encryption_key_cache` attribute (in-memory only)
- Update `create_session()` to extract and cache encryption key
- Add `get_encryption_key()` method
- Update `logout()` to clear encryption key from memory
- Session file stores only: `user_id`, `username`, `timestamp`

### Phase 3: Authentication Commands

#### 3.1 Implement Auth Commands
**File**: `passwault/core/commands/authenticator.py`

Uncomment and implement:
- `register(username, password, email, session_manager)` - Create account
- `login(username, password, session_manager)` - Authenticate and create session
- `logout(session_manager)` - Clear session and keys

Use `get_password_with_mask()` when password not provided via CLI arg.

#### 3.2 Create Authentication Decorator
**New File**: `passwault/core/utils/decorators.py`

Implement `@require_auth` decorator:
- Check if session is active
- Verify encryption key exists in memory
- Return error message if not authenticated
- Apply to: save_password, load_password, delete_password, imagepass commands

### Phase 4: Update Password Operations

#### 4.1 Update Password Manager Repository
**File**: `passwault/core/database/password_manager.py`

Update all methods to:
- Accept `user_id` and `encryption_key` parameters
- Encrypt passwords before saving using `CryptoService`
- Decrypt passwords when loading
- Filter by `user_id` for data isolation
- Handle `UniqueConstraint` violations

Key methods to update:
- `save_password()` - Encrypt before insert
- `get_password_by_resource_name()` - Filter by user_id, decrypt result
- `get_password_by_username()` - Filter by user_id, decrypt result
- `get_all_passwords()` - Filter by user_id, decrypt results

#### 4.2 Update Password Commands
**File**: `passwault/core/commands/password.py`

- Add `@require_auth` decorator to all commands
- Extract `user_id` and `encryption_key` from session_manager
- Pass to repository methods
- Handle missing encryption key (prompt re-login)

### Phase 5: CLI Integration

#### 5.1 Update CLI Parser
**File**: `passwault/core/cli.py`

Add auth subcommand group:
```python
passwault auth register -u <username> [-p <password>] [-e <email>]
passwault auth login -u <username> [-p <password>]
passwault auth logout
```

Update existing commands:
- Pass `session_manager` to all command handlers
- Ensure decorators can check authentication status

#### 5.2 Update Main Entry Point
**File**: `passwault/__main__.py`

- Check for migration on startup
- Initialize session manager
- Create tables if needed

### Phase 6: Data Migration

#### 6.1 Create Migration Script
**New File**: `passwault/core/database/migrations.py`

Implement:
- `check_migration_needed()` - Detect old schema
- `migrate_from_v1_to_v2()` - Migration flow:
  1. Create new tables
  2. Prompt user to register (becomes migration owner)
  3. Encrypt existing plain-text passwords with new encryption key
  4. Migrate all passwords to new user_id
  5. Commit transaction

**User Experience**:
```
$ passwault load_password -n github

[INFO] Database migration required.
[INFO] Please create an account to migrate existing passwords.

Username: john
Master Password: ********

[INFO] Migrating 15 passwords...
[INFO] Migration complete! You are now logged in.
```

### Phase 7: Imagepass Integration

#### 7.1 Update Imagepass Commands
**File**: `passwault/imagepass/embedder.py`

- Uncomment `@require_auth` decorators (lines 226, 251)
- Ensure imagepass encode/decode require active session
- No other changes needed (steganography logic unchanged)

### Phase 8: Additional Commands

#### 8.1 Add Delete Password Command
**New method in**: `passwault/core/commands/password.py`

```python
@require_auth
def delete_password(password_name: str, session_manager: SessionManager)
```

#### 8.2 Add Change Master Password Command
**New method in**: `passwault/core/commands/authenticator.py`

```python
@require_auth
def change_master_password(old_password: str, new_password: str, session_manager: SessionManager)
```

Flow:
1. Verify old password
2. Load all user's passwords (decrypt with old key)
3. Generate new salt
4. Derive new encryption key
5. Re-encrypt all passwords
6. Update user record
7. Update session with new encryption key

---

## Critical Files to Modify

1. `passwault/core/database/models.py` - Database schema
2. `passwault/core/services/crypto_service.py` - NEW: Cryptography operations
3. `passwault/core/database/user_repository.py` - User operations
4. `passwault/core/database/password_manager.py` - Password CRUD
5. `passwault/core/utils/session_manager.py` - Session handling
6. `passwault/core/commands/authenticator.py` - Auth commands
7. `passwault/core/commands/password.py` - Password commands
8. `passwault/core/cli.py` - CLI parser
9. `passwault/core/database/migrations.py` - NEW: Data migration
10. `passwault/core/utils/decorators.py` - NEW: Auth decorator

---

## Security Considerations

### Cryptography Standards
- **Key Derivation**: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023)
- **Password Hashing**: bcrypt with automatic salting (cost factor 12)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Randomness**: `os.urandom()` for cryptographic operations

### Key Security Measures
1. ✅ Master password never stored (only bcrypt hash)
2. ✅ Encryption key exists in memory only during active session
3. ✅ Session timeout (10 minutes) auto-locks vault
4. ✅ Unique nonce per password encryption (prevents replay attacks)
5. ✅ User data isolation via foreign keys
6. ✅ No passwords in logs or error messages

### Attack Mitigation
- **SQL Injection**: SQLAlchemy ORM parameterization
- **Timing Attacks**: bcrypt constant-time comparison
- **Brute Force**: High KDF iterations (600k)
- **Memory Dumps**: Clear keys on logout/timeout
- **Database Theft**: Passwords encrypted with key derived from master password

### Optional Enhancement
Consider enabling SQLCipher for full database encryption (already in dependencies).

---

## Testing Strategy

### Unit Tests (New Files)

1. **`tests/test_crypto_service.py`**
   - Key derivation with test vectors
   - Encryption/decryption roundtrip
   - bcrypt hashing and verification
   - Salt randomness

2. **`tests/test_user_repository.py`**
   - User registration
   - Duplicate username handling
   - Authentication success/failure
   - Encryption key derivation

3. **`tests/test_password_repository.py`**
   - Encrypted password save/load
   - User data isolation
   - Decryption with correct key

4. **`tests/test_session_manager.py`**
   - Session creation with encryption key
   - Key in-memory storage
   - Logout clears keys
   - Session expiration

5. **`tests/test_auth_commands.py`**
   - Register/login/logout flows
   - Decorator enforcement

### Integration Tests

1. **Full User Flow**:
   ```
   register → login → save_password → logout → login → load_password
   ```

2. **Migration Test**:
   - Create old schema DB with plain-text passwords
   - Run migration
   - Verify encrypted passwords accessible after login

3. **Multi-User Isolation**:
   - User A saves password
   - User B cannot access User A's password

---

## Future REST API Readiness

### Repository Pattern Benefits
Current architecture uses repository pattern (UserRepository, PasswordRepository), which provides clean abstraction for future API integration.

**Current**: `CLI → Repository → SQLAlchemy → SQLite`
**Future**: `CLI → Repository → HTTP Client → REST API → Database`

### Design Decisions for Client-Server Split

1. **Encryption Stays Client-Side**: Master password and encryption key never sent to server
2. **Server Stores Encrypted Blobs**: Server has no decryption capability
3. **Token-Based Auth**: Use JWT tokens for API authentication
4. **Zero-Knowledge Architecture**: Server cannot decrypt user passwords

### Planned API Endpoints (Future Reference)

```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh

GET    /api/v1/passwords
POST   /api/v1/passwords
GET    /api/v1/passwords/:id
PUT    /api/v1/passwords/:id
DELETE /api/v1/passwords/:id

POST   /api/v1/passwords/generate
POST   /api/v1/imagepass/encode
POST   /api/v1/imagepass/decode
```

### Migration Path

**Phase 1** (This Plan): Local CLI with SQLite
**Phase 2** (Future): Add REST API server (Flask/FastAPI)
**Phase 3** (Future): CLI switches to API backend via config flag

---

## Verification & Testing

### Manual Testing Checklist

1. **Authentication**
   - [ ] Register new user with username and master password
   - [ ] Login with correct credentials
   - [ ] Login fails with incorrect password
   - [ ] Logout clears session

2. **Password Operations**
   - [ ] Save password while logged in
   - [ ] Load password and verify decryption
   - [ ] Save password fails when not logged in
   - [ ] List all passwords for current user

3. **Session Management**
   - [ ] Session persists after CLI exit and re-launch
   - [ ] Session expires after 10 minutes of inactivity
   - [ ] Logout clears session file

4. **Multi-User Support**
   - [ ] Register second user
   - [ ] User A cannot see User B's passwords
   - [ ] Each user's passwords decrypt correctly

5. **Migration**
   - [ ] Create DB with old schema and plain-text passwords
   - [ ] Run app, trigger migration
   - [ ] All old passwords accessible after migration
   - [ ] Old passwords now encrypted

6. **Imagepass**
   - [ ] Encode password in image while logged in
   - [ ] Decode password from image
   - [ ] Imagepass requires authentication

### Automated Test Execution

```bash
# Run all tests
make test

# Run with coverage
uv run pytest --cov=passwault tests/

# Run specific test suite
uv run pytest tests/test_crypto_service.py -v
```

---

## Implementation Notes

### Database Connection
- Use existing `SessionLocal()` from models.py
- Close sessions in finally blocks
- Wrap critical operations in transactions

### Error Handling
- Return `Result` objects (ok, result) from repositories
- Display user-friendly errors via Logger
- Never log sensitive data (passwords, keys)

### Backward Compatibility
- Migration script handles existing databases
- New users start with encrypted storage
- No manual intervention required

### Code Style
- Follow existing black formatting
- Pass flake8 linting
- Use type hints for new code
- Add docstrings to public methods

---

## Summary

This plan transforms Passwault from a single-user, plain-text password manager into a secure, multi-user system with proper encryption at rest. The implementation preserves the unique image steganography feature while establishing a foundation for future client-server architecture.

**Key Outcomes**:
- 🔒 Master password-based vault encryption
- 👥 Multi-user support with data isolation
- 🛡️ AES-256-GCM encryption for all stored passwords
- 🔑 Zero-knowledge architecture (keys never persisted)
- 🖼️ Preserved image steganography functionality
- 🚀 Repository pattern ready for REST API integration
- ✅ Automated migration from plain-text to encrypted storage
