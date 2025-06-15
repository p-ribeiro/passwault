import argparse
<<<<<<< HEAD
import sys
from email.mime import image
=======
from email.mime import image
import sys
>>>>>>> 429d2c0b719b851541ad1b6fb8681aa686ede0d1
from json import load

from numpy import imag, ma, require

from passwault.core.commands.authenticator import login, logout, register
from passwault.core.commands.password import generate_pw, load_pw, save_pw
from passwault.core.utils import session_manager
from passwault.core.utils.database import init_db
from passwault.core.utils.file_handler import valid_file, valid_image_file
from passwault.core.utils.logger import Logger
from passwault.core.utils.session_manager import SessionManager
from passwault.imagepass import embedder
from passwault.imagepass.embedder import Embedder

session = {"logged_in": False}


def handle_imagepass(args, session_manager):
<<<<<<< HEAD

=======
    
>>>>>>> 429d2c0b719b851541ad1b6fb8681aa686ede0d1
    embedder = Embedder()
    if args.option == "encode":
        return embedder.encode(
                            image_path = args.image_path,
                            password = args.password,
                            session_manager = session_manager)
    else:
        return embedder.decode(
                            image_path = args.image_path,
                            session_manager = session_manager)

def cli():
    session_manager = SessionManager()
    session_manager.expire_session()

    try:
        parser = argparse.ArgumentParser(description="""---- PASSWAULT: a password manager""")
        subparsers = parser.add_subparsers(help="Available commands")

        # register subcommand
        register_parser = subparsers.add_parser("register", help="register a new user")
        register_parser.add_argument("-u", "--username", type=str, required=True, help="your username")
        register_parser.add_argument("-p", "--password", type=str, help="your password")
        register_parser.add_argument("-r", "--role", required=True, type=str, help="your role")
        register_parser.set_defaults(func=lambda args: register(args.username, args.password, args.role))

        # login subcommand
        login_parser = subparsers.add_parser("login", help="login into the system")
        login_parser.add_argument("-u", "--username", type=str, required=True, help="your username")
        login_parser.add_argument("-p", "--password", type=str, help="your password")
        login_parser.set_defaults(func=lambda args: login(args.username, args.password, session_manager))

        # logout subcommand
        logout_parser = subparsers.add_parser("logout", help="logout from the system")
        logout_parser.set_defaults(func=lambda _: logout(session_manager))

        # generate subcommand
        generate_parser = subparsers.add_parser("generate", help="Generates a new password")
        generate_parser.add_argument("-s", action="store_true", help="the password must have symbols")
        generate_parser.add_argument("-d", action="store_true", help="the password must have digits")
        generate_parser.add_argument("-u", action="store_true", help="the password must have uppercases")
        generate_parser.add_argument("-l", default=10, type=int, help="the password length", metavar="LENGTH")
        generate_parser.set_defaults(func=lambda args: generate_pw(args.l, args.s, args.d, args.u))

        # save_password subcommand
        save_password_parser = subparsers.add_parser("save_password", help="Saves a new password to database")
        save_password_parser.add_argument("-p", "--password", type=str, help="the password to be saved")
        save_password_parser.add_argument("-n", "--password-name", type=str, help="the value identify the password")
        save_password_parser.add_argument("-f", "--file", type=valid_file, help="the file with the list of passswords")
        save_password_parser.set_defaults(func=lambda args: save_pw(args.password, args.password_name, args.file, session_manager))

        # load_password subcommand
        load_password_parser = subparsers.add_parser("load_password", help="Gets the password from database")
        load_password_parser.add_argument("-n", "--password-name", type=str, help="the password identifier")
        load_password_parser.add_argument("-a", "--all-passwords", action="store_true", help="return all passwords for user")
        load_password_parser.set_defaults(func=lambda args: load_pw(args.password_name, args.all_passwords, session_manager))

        # encode image with imagepass module
        imagepass_parser = subparsers.add_parser("imagepass", help="Encode or Decode passwords in Image")
        imagepass_parser.add_argument("option", choices=["encode", "decode"], help="Choose 'encode' to save a password inside an image or 'decode' to retrieve a password from an encoded image")
        imagepass_parser.add_argument("image_path", type=valid_image_file, help="the image file")
        imagepass_parser.add_argument("-p", "--password", help="the password to be encoded")
        imagepass_parser.set_defaults(func=lambda args: handle_imagepass(args, session_manager))
<<<<<<< HEAD

        args = parser.parse_args()
=======
>>>>>>> 429d2c0b719b851541ad1b6fb8681aa686ede0d1

        args = parser.parse_args()

        if len(sys.argv) == 1:
            Logger.error("No arguments provided. Please specify at least one argument.")
            parser.print_help()
            return

        args.func(args)

    except argparse.ArgumentError as e:
        Logger.error(e)


if __name__ == "__main__":
    init_db()
    cli()
