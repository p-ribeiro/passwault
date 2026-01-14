"""CLI interface for Passwault password manager.

This module provides the command-line interface for all Passwault operations
including authentication, password management, password generation, and
image steganography.
"""

import argparse

from passwault.core.commands.authenticator import (
    change_master_password,
    login,
    logout,
    register,
)
from passwault.core.commands.password import (
    delete_password,
    generate_password,
    load_password,
    save_password,
    update_password,
)
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
        login_parser = auth_subparsers.add_parser(
            "login", help="Login to your account"
        )
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
        generate_parser.set_defaults(
            func=lambda args: generate_password(
                password_length=args.length,
                has_symbols=not args.no_symbols,
                has_digits=not args.no_digits,
                has_uppercase=not args.no_uppercase,
            )
        )

        # ====================================
        # PASSWORD MANAGEMENT
        # ====================================
        save_parser = subparsers.add_parser(
            "save", help="Save a password (requires authentication)"
        )
        save_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name/identifier (e.g., 'github')",
        )
        save_parser.add_argument(
            "-p", "--password", type=str, required=True, help="Password to save"
        )
        save_parser.add_argument(
            "-u",
            "--username",
            type=str,
            help="Username associated with this password",
        )
        save_parser.add_argument(
            "-w", "--website", type=str, help="Website URL (optional)"
        )
        save_parser.add_argument(
            "-d", "--description", type=str, help="Description (optional)"
        )
        save_parser.add_argument(
            "-t", "--tags", type=str, help="Comma-separated tags (optional)"
        )
        save_parser.set_defaults(
            func=lambda args: save_password(
                resource_name=args.resource_name,
                password=args.password,
                username=args.username,
                website=args.website,
                description=args.description,
                tags=args.tags,
                session_manager=session_manager,
            )
        )

        # Load password subcommand
        load_parser = subparsers.add_parser(
            "load", help="Load password(s) (requires authentication)"
        )
        load_parser.add_argument(
            "-n", "--resource-name", type=str, help="Resource name to load"
        )
        load_parser.add_argument(
            "-u", "--username", type=str, help="Load all passwords for this username"
        )
        load_parser.add_argument(
            "-a", "--all", action="store_true", help="Load all passwords"
        )
        load_parser.set_defaults(
            func=lambda args: load_password(
                resource_name=args.resource_name,
                username=args.username,
                all_passwords=args.all,
                session_manager=session_manager,
            )
        )

        # Update password subcommand
        update_parser = subparsers.add_parser(
            "update", help="Update an existing password (requires authentication)"
        )
        update_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name to update",
        )
        update_parser.add_argument(
            "-p", "--password", type=str, required=True, help="New password"
        )
        update_parser.add_argument(
            "-u", "--username", type=str, help="Update username (optional)"
        )
        update_parser.add_argument(
            "-w", "--website", type=str, help="Update website (optional)"
        )
        update_parser.add_argument(
            "-d", "--description", type=str, help="Update description (optional)"
        )
        update_parser.add_argument(
            "-t", "--tags", type=str, help="Update tags (optional)"
        )
        update_parser.set_defaults(
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
        delete_parser = subparsers.add_parser(
            "delete", help="Delete a password (requires authentication)"
        )
        delete_parser.add_argument(
            "-n",
            "--resource-name",
            type=str,
            required=True,
            help="Resource name to delete",
        )
        delete_parser.set_defaults(
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
