import os

from vault.core.authenticator import login, register
from vault.core.password_ops import load_pw, save_pw
from vault.core.utils.database import init_db


def start():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n---- PASSWAULT ---")

        action = input("Choose an action (register|login|exit):  ").strip().lower()

        if action == "register":
            username = input("Enter Username: ")
            password = input("Enter Password: ")
            role = input("Enter role (e.g., admin/user): ")
            register(username, password, role)
            break

        elif action == "login":
            username = input("Enter Username: ")
            password = input("Enter Password: ")
            login(username, password, logged_in)
            break

        elif action == "exit":
            exit(0)

        else:
            print("Invalid action. Please try again.")
            input("Press enter to continue...")


def logged_in(user_id: int):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n---- PASSWAULT ---")

        action = input("Choose an action (generate|save|load|exit)").strip().lower()

        if action == "generate":
            break
        elif action == "save":
            password_name = input("Insert password name (e.g., gmail.com): ")
            password = input("Insert password: ")
            save_pw(user_id, password, password_name)
            break

        elif action == "load":
            password_name = input("Insert password name (e.g., gmail.com)")
            load_pw(user_id, password_name)
            break

        elif action == "exit":
            exit(0)

        else:
            print("Invalid action. Please try again.")
            input("Press enter to continue...")


if __name__ == "__main__":
    init_db()
    start()
