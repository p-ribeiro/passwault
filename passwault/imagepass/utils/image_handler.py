from pathlib import Path
from typing import List, Tuple

from PIL import Image


class ImageHandler:
    def __init__(self, image_path: Path) -> None:
        self.image_path: Path = image_path
        self.image_name: str = image_path.stem
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

    def replace_band(self, band: str, band_values: List[int]):

        with Image.open(self.image_path) as im:
            bands = im.split()

        modified_band_image = Image.new("L", (self.width, self.height))
        modified_band_image.putdata(band_values)

        print(list(modified_band_image.getdata())[:8])  # Print first 10 pixels

        try:
            match band:
                case "R":
                    modified_image = Image.merge(
                        "RGB", (modified_band_image, bands[1], bands[2])
                    )
                case "G":
                    modified_image = Image.merge(
                        "RGB", (bands[0], modified_band_image, bands[2])
                    )
                case "B":
                    modified_image = Image.merge(
                        "RGB", (bands[0], bands[1], modified_band_image)
                    )
                case "A":
                    modified_image = Image.merge(
                        "RGBA", (bands[0], bands[1], bands[2], modified_band_image)
                    )

            modified_image.save(f"results/enc_{self.image_name}.png", format="PNG")

        except Exception as e:
            print(e)
