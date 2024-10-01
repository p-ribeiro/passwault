import base64
from pathlib import Path
from random import choice
from typing import List

from imagepass.utils.utils import password_generator

from .utils.image_handler import ImageHandler


class Embedder:
    def __init__(self, image_path: str, password: str | None = None) -> None:
        self.image_path = Path(image_path)
        self.password = password
        ...

    def _create_header(self, bands: list[str], key: str) -> str:

        # header format
        # <band>[-<band>]|<key>
        header = "-".join(bands) + "|" + key
        return chr(2) + base64.b64encode(header.encode()).decode('ascii') + chr(3)

    def _get_header(self, band_values: List[int]) -> str | None:
        def _chunks_of_eight(lst: List[int]):
            for i in range(0, len(lst), 8):
                yield lst[i : i + 8]

        start = True
        header = ""
        for bytes in _chunks_of_eight(band_values):
            byte_value = "".join([str(byte & 1) for byte in bytes])
            byte_int = int(byte_value, 2)
            if start:
                if byte_int != 2:
                    return None
                start = False
                continue

            if byte_int == 3:
                return header

            header += chr(byte_int)

    @staticmethod
    def _key_spacing_generator(key: str):
        cnt = 0
        key_size = len(key)
        while True:
            yield ord(key[cnt % key_size])
            cnt += 1

    def _embed_message_lsb(self, source_bytes: bytes, target_bytes: List[int], key: str) -> None:
        """Embed each bit of `source_bytes` into the least significant bit (LSB) of `target_bytes` in-place.

        Args:
            source_bytes (bytes): the bytes to be embedded into the target.
            target_bytes (List[int]): the bytearray into which the source bytes will be embedded.
        """

        target_lenght = len(target_bytes)
        source_bit_idx = 0
        last_byte = ""
        header = True
        keyed_spacer = self._key_spacing_generator(key)

        for byte in source_bytes:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                last_byte += str(bit)

                if source_bit_idx < target_lenght:

                    if bit:
                        target_bytes[source_bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[source_bit_idx] &= ~1  # clear LSB to 0

                if len(last_byte) == 8:
                    if int(last_byte, 2) == 3:
                        header = False
                    last_byte = ""

                if header:
                    source_bit_idx += 1
                else:
                    source_bit_idx += next(keyed_spacer)

    def _retrieve_message_lsb(self, source_bytes: List[int], key: str) -> None:

        keyed_spacer = self._key_spacing_generator(key)
        password = False
        source_bit_idx = 0
        last_byte = ""
        result = ""
        while source_bit_idx < len(source_bytes):
            bit = source_bytes[source_bit_idx] & 1
            last_byte += str(bit)

            if password:
                source_bit_idx += next(keyed_spacer)
                if len(last_byte) == 8:
                    result += chr(int(last_byte, 2))
                    last_byte = ""
                if len(result) == 15:  # Temp solution
                    return result
            else:
                if len(last_byte) == 8:
                    if int(last_byte, 2) == 3:
                        password = True
                        source_bit_idx += next(keyed_spacer)
                        last_byte = ""
                        continue
                    last_byte = ""
                source_bit_idx += 1

    def decode(self):
        image_handler = ImageHandler(self.image_path)
        for band in image_handler.bands.keys():
            band_values = image_handler.get_band_values(band)

            header = self._get_header(band_values)

            if header:
                header_decoded = base64.b64decode(header.encode('ascii')).decode()
                bands, key = header_decoded.split('|')
                password = self._retrieve_message_lsb(band_values, key)
                print(password)

    def encode(self):
        image_handler = ImageHandler(self.image_path)
        band_values = {}
        if len(self.password) < image_handler.size:
            # only one band is necessary (default for passwords)
            # but the band is chosen at random
            band = choice(list(image_handler.bands.keys()))
            band_values[band] = image_handler.get_band_values(band)
            key = password_generator(10, True, True, True)

            message = self._create_header([band], key) + self.password

            self._embed_message_lsb(message.encode(), band_values[band], key)
            print(band)
            print(band_values[band][:8])

            image_handler.replace_band(band, band_values[band])

            # print(len(bytearray(R_values)))
        else:
            # WIP
            pass
