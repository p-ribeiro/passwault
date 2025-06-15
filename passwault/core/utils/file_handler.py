import argparse
from ast import arg
import csv
from email.mime import image
import json
from multiprocessing import Value
from pathlib import Path
from shutil import ExecError
from typing import List, Tuple

from passwault.core.commands import password
from passwault.core.utils.logger import Logger

ALLOWED_EXT = ['.csv', '.txt', '.json']

VALID_IMAGE_EXTENSIONS = ['.jpg', '.png', '.gif', '.jpeg', '.tiff', '.bmp']


def valid_image_file(file: str) -> bool:
    image_file_path = Path(file)
    
    if not image_file_path.exists():
        raise argparse.ArgumentTypeError("Invalid file path")
    
    if image_file_path.suffix not in VALID_IMAGE_EXTENSIONS:
        raise argparse.ArgumentTypeError(f"File must have one of the following extension: {'.'.join(VALID_IMAGE_EXTENSIONS)}")
    
    return file
    
def valid_file(file: str) -> bool:
    file_path = Path(file)

    if not file_path.exists():
        raise argparse.ArgumentTypeError("Invalid file path")

    if file_path.suffix not in ALLOWED_EXT:
        raise argparse.ArgumentTypeError(f"File must have one of the following extensions: {','.join(ALLOWED_EXT)}")

    return file

def _read_csv(file_path: Path):
    pw_pairs = []
    try:
        with open(file_path, 'r', newline='') as csv_file:
            sample = csv_file.read(2048)
            csv_file.seek(0)
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(sample)
            
            has_header = sniffer.has_header(sample)
            
            reader = csv.reader(csv_file, dialect=dialect)
            if has_header:
                header = next(reader)
                print(f"{header=}")
            
            for row in reader:
                pw_pairs.append(tuple(row))
            
            return tuple(pw_pairs)
            
            
    except Exception as e:
        raise ValueError(f"Error with '{file_path.name}': {str(e)}")
        


def read_file(file: str) -> Tuple[Tuple[str, str]] | None:
    file_path = Path(file)
    file_suffix = file_path.suffix

    if file_suffix == ".txt":
        ...

    if file_suffix == ".csv":
        result = _read_csv(file_path)
        return result
        

    if file_suffix == ".json":
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                password_names = list(data.keys())
                passwords = list(data.values())

                if password_names == [] or passwords == []:
                    return None

                return tuple(zip(password_names, passwords))

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
