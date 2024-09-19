from pathlib import Path

from .utils.image_handler import ImageHandler


class Encoder:
    def __init__(self, image_path: str, password: str) -> None:
        self.image_path = Path(image_path)
        self.password = password
        ...

    def encode(self):
        image_handler = ImageHandler(self.image_path)
