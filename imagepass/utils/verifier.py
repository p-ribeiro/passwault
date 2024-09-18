from pathlib import Path


def verify_image_path(image_path: str):
    is_file = Path(image_path).is_file()

    return is_file


def get_file_extension(image_path: str):
    extension = Path(image_path).suffix.lower()

    return extension
