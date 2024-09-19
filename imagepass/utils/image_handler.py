from pathlib import Path
from typing import List, Tuple

from PIL import Image


class ImageHandler:
    def __init__(self, image_path: Path) -> None:
        self.image_path: Path = image_path
        self.width, self.height = self._get_image_dimensions()
        self.bands: dict[str, int] = self._get_image_bands()
        self.size = self.width * self.height

    def _get_image_dimensions(self) -> Tuple[int, ...]:
        with Image.open(self.image_path) as im:
            width, height = im.size

        print(width, height)
        return (width, height)

    def _get_image_bands(self) -> dict[str, int]:
        bands = {}

        with Image.open(self.image_path) as im:
            for idx, band in enumerate(im.getbands()):
                bands[band] = idx

        return bands

    def get_band_values(self, band: str) -> List[int]:
        if band not in self.bands.keys():
            raise ValueError(f"Band '{band}' is not valid")

        with Image.open(self.image_path) as im:
            band_values = im.getdata(self.bands[band])

        return list(band_values)
