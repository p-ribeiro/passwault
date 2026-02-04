from pathlib import Path
from typing import List, Optional, Tuple

from PIL import Image


class ImageHandler:
    def __init__(self, image_path: Path, output_dir: Optional[Path] = None) -> None:
        self.image_path: Path = image_path
        self._image = Image.open(image_path)
        self._image.load()

        self.result_dir: Path = (
            output_dir or Path(__file__).resolve().parents[3] / "data" / "results"
        )
        self.image_name: str = image_path.stem
        self.image_suffix: str = image_path.suffix.lstrip(".")
        self.width, self.height = self._get_image_dimensions()
        self.bands: dict[str, int] = self._get_image_bands()
        self.size = self.width * self.height

    def _get_image_dimensions(self) -> Tuple[int, int]:
        return self._image.size
    
    def _get_image_bands(self) -> dict[str, int]:
        return {band:idx for idx, band in enumerate(self._image.getbands())}

    def get_band_values(self, band: str) -> List[int]:
        if band not in self.bands:
            raise ValueError(f"Band '{band}' is not valid")

        return list(self._image.getdata(self.bands[band]))

    def replace_band(self, band: str, band_values: List[int]) -> Image.Image:
        # only works for PNG / lossless images

        if band not in self.bands:
            raise ValueError(f"Band '{band}' is not valid")

        if self.image_suffix.lower() in ("jpg", "jpeg"):
            raise TypeError(
                f"The band cannot be replaced for the file type: {self.image_suffix}"
            )

        bands = self._image.split()

        modified_band_image = Image.new("L", (self.width, self.height))
        modified_band_image.putdata(band_values)
        
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
            case "L":
                modified_image = modified_band_image
                
            case _:                                               
                raise ValueError(f"Band '{band}' is not supported for merging")                                         
                    
        return modified_image


    def save_image_to_file(self, image: Image.Image) -> str:
        filename = f"{self.image_name}.{self.image_suffix}"
        image.save(self.result_dir / filename, format=self.image_suffix)
        return str(self.result_dir / filename)
