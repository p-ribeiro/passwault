"""CLI interface for Passwault password manager.

This module provides the command-line interface for all Passwault operations
including authentication, password management, password generation, and
image steganography.
"""

import argparse

from datetime import datetime
from pathlib import Path

from passwault.core.commands.authenticator import (
    change_master_password,
    login,
    logout,
    register,
)
from passwault.core.commands.password import (
    delete_password,
    generate_and_save,
    generate_password,
    get_password,
    add_password,
    update_password,
)
from passwault.core.services.backup_service import BackupService
from passwault.core.utils.file_handler import valid_image_file
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager
from passwault.imagepass.embedder import Embedder


def handle_imagepass(args, session_manager):
    """Handle imagepass encode/decode operations.

    Args:
        args: Parsed command line arguments
        session_manager: Session manager instance

    Returns:
        Result of encode/decode operation
    """
    embedder = Embedder(args.image_path, session_manager=session_manager)
    if args.option == "encode":
        return embedder.encode(message=args.password, session_manager=session_manager)
    else:
        return embedder.decode(session_manager=session_manager)


def handle_backup_create(args):
    """Handle backup create command."""
    output_dir = Path(args.output_dir) if args.output_dir else None
    service = BackupService(backup_dir=output_dir)

    try:
        backup_path = service.create_backup(compress=not args.no_compress)
        Logger.info(f"Backup created: {backup_path}")
    except Exception as e:
        Logger.error(f"Backup failed: {e}")


def handle_backup_list(args):
    """Handle backup list command."""
    service = BackupService()
    backups = service.list_backups()

    if not backups:
        Logger.info("No backups found")
        return

    Logger.info(f"Found {len(backups)} backup(s):\n")
    for backup in backups:
        size_mb = backup.stat().st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(backup.stat().st_mtime)
        print(f"  {backup.name:40} {size_mb:8.2f} MB  {mtime:%Y-%m-%d %H:%M:%S}")


def handle_backup_restore(args):
    """Handle backup restore command."""
    service = BackupService()

    # Check if it's a full path or just filename
    backup_path = Path(args.backup_file)
    if not backup_path.is_absolute():
        backup_path = service.backup_dir / args.backup_file

    if not backup_path.exists():
        Logger.error(f"Backup file not found: {backup_path}")
        return

    # Confirmation prompt
    if not args.yes:
        response = input(
            f"This will restore the database from {backup_path.name}. "
            "Current data will be backed up. Continue? [y/N]: "
        )
        if response.lower() != "y":
            Logger.info("Restore cancelled")
            return

    try:
        service.restore_backup(backup_path)
        Logger.info("Database restored successfully")
    except Exception as e:
        Logger.error(f"Restore failed: {e}")


def handle_backup_cleanup(args):
    """Handle backup cleanup command."""
    service = BackupService()

    try:
        removed = service.cleanup_old_backups(args.retention_days)
        Logger.info(f"Removed {removed} old backup(s)")
    except Exception as e:
        Logger.error(f"Cleanup failed: {e}")


def handle_generate(args, session_manager):
    """Handle generate command with optional --save flag.

    Routes to either simple generate_password() or interactive
    generate_and_save() based on --save flag.

    Args:
        args: Parsed command line arguments
        session_manager: Session manager instance
    """
    if args.save:
        return generate_and_save(
            session_manager=session_manager,
            password_length=args.length,
            has_symbols=not args.no_symbols,
            has_digits=not args.no_digits,
            has_uppercase=not args.no_uppercase,
        )
    else:
        return generate_password(
            password_length=args.length,
            has_symbols=not args.no_symbols,
            has_digits=not args.no_digits,
            has_uppercase=not args.no_uppercase,
        )


def cli(args=None, session_manager=None):
    """Main CLI entry point.

    Args:
        args: Command line arguments (None for sys.argv)
        session_manager: Session manager instance (created if None)

    Returns:
        Result of command execution
    """
    # Initialize session manager if not provided
    if session_manager is None:
        session_manager = SessionManager()

    try:
        parser = argparse.ArgumentParser(
            description="PASSWAULT: A secure password manager with encryption",
            prog="passwault",
        )
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # ====================================
        # AUTHENTICATION COMMANDS
        # ====================================
        auth_parser = subparsers.add_parser(
            "auth", help="Authentication commands (register, login, logout)"
        )
        auth_subparsers = auth_parser.add_subparsers(
            dest="auth_command", help="Authentication operations"
        )

        # Register subcommand
        register_parser = auth_subparsers.add_parser(
            "register", help="Register a new user account"
        )
        register_parser.add_argument(
            "-u", "--username", type=str, required=True, help="Your username"
        )
        register_parser.add_argument(
            "-p",
            "--password",
            type=str,
            help="Your master password (will prompt if not provided)",
        )
        register_parser.add_argument(
            "-e", "--email", type=str, help="Your email address (optional)"
        )
        register_parser.set_defaults(
            func=lambda args: register(
                args.username, args.password, args.email, session_manager
            )
        )

        # Login subcommand
        login_parser = auth_subparsers.add_parser("login", help="Login to your account")
        login_parser.add_argument(
            "-u", "--username", type=str, required=True, help="Your username"
        )
        login_parser.add_argument(
            "-p",
            "--password",
            type=str,
            help="Your master password (will prompt if not provided)",
        )
        login_parser.set_defaults(
            func=lambda args: login(args.username, args.password, session_manager)
        )

        # Logout subcommand
        logout_parser = auth_subparsers.add_parser(
            "logout", help="Logout from current session"
        )
        logout_parser.set_defaults(func=lambda args: logout(session_manager))

        # Change master password subcommand
        change_password_parser = auth_subparsers.add_parser(
            "change-password",
            help="Change your master password (requires authentication)",
        )
        change_password_parser.add_argument(
            "-o",
            "--old-password",
            type=str,
            help="Current master password (will prompt if not provided)",
        )
        change_password_parser.add_argument(
            "-n",
            "--new-password",
            type=str,
            help="New master password (will prompt if not provided)",
        )
        change_password_parser.set_defaults(
            func=lambda args: change_master_password(
                args.old_password, args.new_password, session_manager
            )
        )

        # ====================================
        # PASSWORD GENERATION
        # ====================================
        generate_parser = subparsers.add_parser(
            "generate", help="Generate a secure random password"
        )
        generate_parser.add_argument(
            "-l",
            "--length",
            default=16,
            type=int,
            help="Password length (default: 16)",
        )
        generate_parser.add_argument(
            "--no-symbols",
            action="store_true",
            help="Exclude symbols from password",
        )
        generate_parser.add_argument(
            "--no-digits", action="store_true", help="Exclude digits from password"
        )
        generate_parser.add_argument(
            "--no-uppercase",
            action="store_true",
            help="Exclude uppercase letters from password",
        )
        generate_parser.add_argument(
            "--save",
            action="store_true",
            help="Interactive mode: regenerate until satisfied, then save to database (requires login)",
        )
        generate_parser.set_defaults(
            func=lambda args: handle_generate(args, session_manager)
        )

        # ====================================
        # PASSWORD MANAGEMENT
        # ====================================
        add_password_parser = subparsers.add_parser(
            "add", help="Add a password (requires authentication)"
        )
        add_password_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name/identifier (e.g., 'github')",
        )
        add_password_parser.add_argument(
            "-p", "--password", type=str, required=True, help="Password to save"
        )
        add_password_parser.add_argument(
            "-u",
            "--username",
            type=str,
            help="Username associated with this password",
        )
        add_password_parser.add_argument(
            "-w", "--website", type=str, help="Website URL (optional)"
        )
        add_password_parser.add_argument(
            "-d", "--description", type=str, help="Description (optional)"
        )
        add_password_parser.add_argument(
            "-t", "--tags", type=str, help="Comma-separated tags (optional)"
        )
        add_password_parser.set_defaults(
            func=lambda args: add_password(
                resource_name=args.resource_name,
                password=args.password,
                username=args.username,
                website=args.website,
                description=args.description,
                tags=args.tags,
                session_manager=session_manager,
            )
        )

        # get password subcommand
        get_password_parser = subparsers.add_parser(
            "get", help="Get password(s) (requires authentication)"
        )
        get_password_parser.add_argument(
            "-n", "--resource-name", type=str, help="Resource name to load"
        )
        get_password_parser.add_argument(
            "-u", "--username", type=str, help="Load all passwords for this username"
        )
        get_password_parser.add_argument(
            "-a", "--all", action="store_true", help="Load all passwords"
        )
        get_password_parser.set_defaults(
            func=lambda args: get_password(
                resource_name=args.resource_name,
                username=args.username,
                all_passwords=args.all,
                session_manager=session_manager,
            )
        )

        # Update password subcommand
        update_password_parser = subparsers.add_parser(
            "update", help="Update an existing password (requires authentication)"
        )
        update_password_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name to update",
        )
        update_password_parser.add_argument(
            "-p", "--password", type=str, required=True, help="New password"
        )
        update_password_parser.add_argument(
            "-u", "--username", type=str, help="Update username (optional)"
        )
        update_password_parser.add_argument(
            "-w", "--website", type=str, help="Update website (optional)"
        )
        update_password_parser.add_argument(
            "-d", "--description", type=str, help="Update description (optional)"
        )
        update_password_parser.add_argument(
            "-t", "--tags", type=str, help="Update tags (optional)"
        )
        update_password_parser.set_defaults(
            func=lambda args: update_password(
                resource_name=args.resource_name,
                new_password=args.password,
                username=args.username,
                website=args.website,
                description=args.description,
                tags=args.tags,
                session_manager=session_manager,
            )
        )

        # Delete password subcommand
        delete_password_parser = subparsers.add_parser(
            "delete", help="Delete a password (requires authentication)"
        )
        delete_password_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name to delete",
        )
        delete_password_parser.set_defaults(
            func=lambda args: delete_password(
                resource_name=args.resource_name, session_manager=session_manager
            )
        )

        # ====================================
        # IMAGE STEGANOGRAPHY
        # ====================================
        imagepass_parser = subparsers.add_parser(
            "imagepass",
            help="Encode or decode passwords in images (requires authentication)",
        )
        imagepass_parser.add_argument(
            "option",
            choices=["encode", "decode"],
            help="Choose 'encode' to hide password in image or 'decode' to retrieve it",
        )
        imagepass_parser.add_argument(
            "image_path", type=valid_image_file, help="Path to image file"
        )
        imagepass_parser.add_argument(
            "-p",
            "--password",
            help="Password to encode (required for encode, ignored for decode)",
        )
        imagepass_parser.set_defaults(
            func=lambda args: handle_imagepass(args, session_manager)
        )

        # ====================================
        # BACKUP COMMANDS
        # ====================================
        backup_parser = subparsers.add_parser(
            "backup", help="Database backup operations"
        )
        backup_subparsers = backup_parser.add_subparsers(
            dest="backup_command", help="Backup operations"
        )

        # Create backup subcommand
        create_backup_parser = backup_subparsers.add_parser(
            "create", help="Create a database backup"
        )
        create_backup_parser.add_argument(
            "--no-compress",
            action="store_true",
            help="Don't compress the backup file",
        )
        create_backup_parser.add_argument(
            "-o",
            "--output-dir",
            type=str,
            help="Custom output directory for backup",
        )
        create_backup_parser.set_defaults(func=lambda args: handle_backup_create(args))

        # List backups subcommand
        list_backup_parser = backup_subparsers.add_parser(
            "list", help="List available backups"
        )
        list_backup_parser.set_defaults(func=lambda args: handle_backup_list(args))

        # Restore backup subcommand
        restore_backup_parser = backup_subparsers.add_parser(
            "restore", help="Restore database from backup"
        )
        restore_backup_parser.add_argument(
            "backup_file",
            type=str,
            help="Path to backup file or backup filename",
        )
        restore_backup_parser.add_argument(
            "-y",
            "--yes",
            action="store_true",
            help="Skip confirmation prompt",
        )
        restore_backup_parser.set_defaults(func=lambda args: handle_backup_restore(args))

        # Cleanup old backups subcommand
        cleanup_backup_parser = backup_subparsers.add_parser(
            "cleanup", help="Remove old backups"
        )
        cleanup_backup_parser.add_argument(
            "--retention-days",
            type=int,
            default=30,
            help="Keep backups from last N days (default: 30)",
        )
        cleanup_backup_parser.set_defaults(func=lambda args: handle_backup_cleanup(args))

        # Parse arguments
        parsed_args = parser.parse_args(args)

        # Execute command if func is set
        if hasattr(parsed_args, "func"):
            return parsed_args.func(parsed_args)

        # No command provided, print help
        parser.print_help()

    except argparse.ArgumentError as e:
        Logger.error(str(e))
    except KeyboardInterrupt:
        Logger.info("\nOperation cancelled by user.")
    except Exception as e:
        Logger.error(f"Unexpected error: {str(e)}")
