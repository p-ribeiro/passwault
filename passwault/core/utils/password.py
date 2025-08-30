import sys
import termios
import tty


def get_password_with_mask():
    prompt = "Please insert password: "
    print(prompt, end="", flush=True)
    password = []

    # Saving terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setraw(fd)
        while True:
            char = sys.stdin.read(1)  # reads one character at a time
            if char == "\n" or char == "\r":
                print("\033[2K\033[0G", end="", flush=True)
                break
            elif char == "\x7f":  # backspace character
                if password:
                    print("\b \b", end="", flush=True)
                    password.pop()
            else:
                password.append(char)
                print("*", end="", flush=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(password)
