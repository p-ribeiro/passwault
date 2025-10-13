import argparse
import sys

from passwault.core.utils.app_context import AppContext
from passwault.core.commands.authenticator import login, logout, register
from passwault.core.commands.password import generate_pw, load_pw, save_pw
from passwault.core.utils.file_handler import valid_file, valid_image_file
from passwault.core.utils.logger import Logger
from passwault.imagepass.embedder import Embedder

# session = {"logged_in": False}


def handle_imagepass(args, session_manager):
    embedder = Embedder(args.image_path, session_manager)
    if args.option == "encode":
        return embedder.encode(message=args.password)
    else:
        return embedder.decode()

def validate_save_pw_args(args, parser):
    # if file is given, p/n must not be required
    if args.file:
        return
    # otherwise need both p and n
    if not args.password or not args.password_name:
        parser.error("when not using -f/--file, both -p/--password and -n/--password-name are required")

def cli(ctx: AppContext, args=None):
    try:
        parser = argparse.ArgumentParser(
            description="""---- PASSWAULT: a password manager"""
        )
        subparsers = parser.add_subparsers(help="Available commands")

        # register subcommand
        register_parser = subparsers.add_parser("register", help="register a new user")
        register_parser.add_argument(
            "-u", "--username", type=str, required=True, help="your username"
        )
        register_parser.add_argument("-p", "--password", type=str, help="your password")
        register_parser.add_argument(
            "-r", "--role", required=True, type=str, help="your role"
        )
        register_parser.set_defaults(
            func=lambda args: register(args.username, args.password, args.role, ctx)
        )

        # login subcommand
        login_parser = subparsers.add_parser("login", help="login into the system")
        login_parser.add_argument(
            "-u", "--username", type=str, required=True, help="your username"
        )
        login_parser.add_argument("-p", "--password", type=str, help="your password")
        login_parser.set_defaults(
            func=lambda args: login(args.username, args.password, ctx)
        )

        # logout subcommand
        logout_parser = subparsers.add_parser("logout", help="logout from the system")
        logout_parser.set_defaults(func=lambda _: logout(ctx))

        # generate subcommand
        generate_parser = subparsers.add_parser(
            "generate", help="Generates a new password"
        )
        generate_parser.add_argument(
            "-s", action="store_true", help="the password must have symbols"
        )
        generate_parser.add_argument(
            "-d", action="store_true", help="the password must have digits"
        )
        generate_parser.add_argument(
            "-u", action="store_true", help="the password must have uppercases"
        )
        generate_parser.add_argument(
            "-l", default=10, type=int, help="the password length", metavar="LENGTH"
        )
        generate_parser.set_defaults(
            func=lambda args: generate_pw(args.l, args.s, args.d, args.u)
        )

        # save_password subcommand
        save_password_parser = subparsers.add_parser(
            "save_password", help="Saves a new password to database"
        )
        save_password_parser.add_argument(
            "-p", "--password", type=str, help="the password to be saved"
        )
        save_password_parser.add_argument(
            "-u",
            "--username",
            type=str,
            default=None,
            help="the username or email related to this password",
        )
        save_password_parser.add_argument(
            "-n", "--password-name", type=str, help="the value identify the password"
        )
        save_password_parser.add_argument(
            "-f", "--file", type=valid_file, help="the file with the list of passswords"
        )
        save_password_parser.set_defaults(
            func=lambda args: (
                validate_save_pw_args(args, save_password_parser),   
                save_pw(
                args.username, args.password, args.password_name, args.file, ctx
                )
            )
        )

        # load_password subcommand
        load_password_parser = subparsers.add_parser(
            "load_password", help="Gets the password from database"
        )
        load_password_parser.add_argument(
            "-n", "--password-name", type=str, help="the password identifier"
        )
        load_password_parser.add_argument(
            "-a",
            "--all-passwords",
            action="store_true",
            help="return all passwords for user",
        )
        load_password_parser.set_defaults(
            func=lambda args: load_pw(args.password_name, args.all_passwords, ctx)
        )

        # encode image with imagepass module
        imagepass_parser = subparsers.add_parser(
            "imagepass", help="Encode or Decode passwords in Image"
        )
        imagepass_parser.add_argument(
            "option",
            choices=["encode", "decode"],
            help="Choose 'encode' to save a password inside an image or 'decode' to retrieve a password from an encoded image",
        )
        imagepass_parser.add_argument(
            "image_path", type=valid_image_file, help="the image file"
        )
        imagepass_parser.add_argument(
            "-p", "--password", help="the password to be encoded"
        )
        imagepass_parser.set_defaults(func=lambda args: handle_imagepass(args, ctx))

        parsed_args = parser.parse_args(args)

        if hasattr(parsed_args, "func"):
            return parsed_args.func(parsed_args)
        parser.print_help()
        # if len(sys.argv) == 1:
        #     Logger.error("No arguments provided. Please specify at least one argument.")
        #     parser.print_help()
        #     return
        # parsed_args.func(parsed_args)

    except argparse.ArgumentError as e:
        Logger.error(str(e))
