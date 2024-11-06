import argparse

from passwault.core.commands.authenticator import login, register
from passwault.core.commands.password import generate_pw, load_pw, save_pw
from passwault.core.utils.database import init_db
from passwault.core.utils.session_manager import SessionManager

session = {"logged_in": False}


def cli():
    session_manager = SessionManager()

    parser = argparse.ArgumentParser(description="---- PASSWAULT ----")
    subparsers = parser.add_subparsers(help="Available commands")

    # register subcommand
    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("-u", "--username", type=str, help="your username")
    register_parser.add_argument("-p", "--password", type=str, help="your password")
    register_parser.add_argument("-r", "--role", type=str, help="your role")
    register_parser.set_defaults(func=lambda args: register(args.username, args.password, args.role))

    # login subcommand
    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("-u", "--username", type=str, help="your username")
    login_parser.add_argument("-p", "--password", type=str, help="your password")
    login_parser.set_defaults(func=lambda args: login(args.username, args.password, session_manager))

    args = parser.parse_args()

    args.func(args)


# def start():
#     while True:
#         os.system('cls' if os.name == 'nt' else 'clear')
#         print("\n---- PASSWAULT ---")

#         action = input("Choose an action (register|login|exit):  ").strip().lower()

#         if action == "register":
#             username = input("Enter Username: ")
#             password = input("Enter Password: ")
#             role = input("Enter role (e.g., admin/user): ")
#             register(username, password, role)
#             break

#         elif action == "login":
#             username = input("Enter Username: ")
#             password = input("Enter Password: ")
#             login(username, password, logged_in)
#             break

#         elif action == "exit":
#             exit(0)

#         else:
#             print("Invalid action. Please try again.")
#             input("Press enter to continue...")


# def logged_in(user_id: int):
#     while True:
#         os.system('cls' if os.name == 'nt' else 'clear')
#         print("\n---- PASSWAULT ---")

#         action = input("Choose an action (generate [-s|]|save|load|exit): ").strip().lower()

#         if action == "generate":
#             ...
#         elif action == "save":
#             password_name = input("Insert password name (e.g., gmail.com): ")
#             password = input("Insert password: ")
#             save_pw(user_id, password, password_name)
#             break

#         elif action == "load":
#             password_name = input("Insert password name (e.g., gmail.com): ")
#             load_pw(user_id, password_name)
#             break

#         elif action == "exit":
#             exit(0)

#         else:
#             print("Invalid action. Please try again.")
#             input("Press enter to continue...")


if __name__ == "__main__":
    init_db()
    cli()
