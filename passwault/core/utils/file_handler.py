import argparse
import json
from multiprocessing import Value
from pathlib import Path
from typing import List, Tuple

from passwault.core.commands import password
from passwault.core.utils.logger import Logger

ALLOWED_EXT = ['.csv', '.txt', '.json']


def valid_file(file: str) -> bool:
    file_path = Path(file)

    if not file_path.exists():
        raise argparse.ArgumentTypeError("Invalid file path")

    if file_path.suffix not in ALLOWED_EXT:
        raise argparse.ArgumentTypeError(f"File must have one of the following extensions: {", ".join(ALLOWED_EXT)}")

    return file


def read_file(file: str) -> Tuple[List[str], List[str]] | None:
    file_path = Path(file)
    file_suffix = file_path.suffix

    if file_suffix == ".txt":
        ...

    if file_suffix == ".csv":
        ...

    if file_suffix == ".json":
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                password_names = list(data.keys())
                passwords = list(data.values())

                if password_names == [] or passwords == []:
                    return None

                return (password_names, passwords)

        except Exception as e:
            raise ValueError(f"Error with '{file_path.name}': {str(e)}")


if __name__ == "__main__":
    file = "/home/jd/passvault-project/files/passwords.json"

    try:
        result = read_file(file)
        if result is None:
            print('empty')
            exit(0)
        pn, p = result
        print(pn, p)
    except ValueError as e:
        print(e)
