from pathlib import Path


class Encoder:
    def __init__(self, image_path: str, password: str) -> None:
        self.image_path = Path(image_path)
        self.password = password
        ...

    def encode(self):
        ...
