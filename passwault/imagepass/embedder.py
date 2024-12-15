import base64
from pathlib import Path
from random import choice
from tabnanny import check
from typing import List, Optional

from passwault.core.utils.session_manager import SessionManager, check_session
from passwault.imagepass.utils.utils import password_generator
from .utils.image_handler import ImageHandler

START_OF_HEADER = chr(1)
START_OF_MESSAGE = chr(2)
END_OF_MESSAGE = chr(3)
BYTE_SIZE = 8


class Embedder:
    
    def __init__(self) -> None:
        self.image_path = None
        self.password = None
        self.session = None
        self.user_id = None

    def _create_header(self, bands: list[str], key: str) -> str:

        # header format
        # <band>[-<band>]|<key>

        header = "-".join(bands) + "|" + key

        return START_OF_HEADER + base64.b64encode(header.encode()).decode('ascii')

    def _get_header(self, band_values: List[int]) -> str | None:
        def _chunks_of_eight(lst: List[int]):
            for i in range(0, len(lst), 8):
                yield lst[i : i + 8]

        starting_byte = True
        header = ""
        for bytes in _chunks_of_eight(band_values):
            encoded_byte = "".join([str(byte & 1) for byte in bytes])
            encoded_byte_chr = chr(int(encoded_byte, 2))

            if starting_byte:
                if encoded_byte_chr != START_OF_HEADER:
                    return None
                starting_byte = False
                continue

            if encoded_byte_chr == START_OF_MESSAGE:
                return header

            header += encoded_byte_chr

    @staticmethod
    def _key_spacing_generator(key: str):
        cnt = 0
        key_size = len(key)
        while True:
            yield ord(key[cnt % key_size])
            cnt += 1

    def _insert_message_lsb(self, source_bytes: bytes, target_bytes: List[int], key: str) -> None:
        """In-place embedding of each bit of `source_bytes` into the least significant bit (LSB) of `target_bytes`.

        Args:
            source_bytes (bytes): the bytes to be embedded into the target.
            target_bytes (List[int]): the bytearray into which the source bytes will be embedded.
        """

        target_lenght = len(target_bytes)
        bit_idx = 0
        last_byte = ""
        header = True
        keyed_spacer = self._key_spacing_generator(key)

        for byte in source_bytes:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                last_byte += str(bit)

                if bit_idx < target_lenght:

                    if bit:
                        target_bytes[bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[bit_idx] &= ~1  # clear LSB to 0

                if len(last_byte) == BYTE_SIZE:
                    if chr(int(last_byte, 2)) == START_OF_MESSAGE:
                        header = False
                    last_byte = ""

                if header:
                    bit_idx += 1
                else:
                    bit_idx += next(keyed_spacer)

    def _retrieve_message_lsb(self, source_bytes: List[int], key: str) -> None:

        keyed_spacer = self._key_spacing_generator(key)
        is_message = False
        source_bit_idx = 0
        decoded_byte = ""
        result = ""
        while source_bit_idx < len(source_bytes):
            bit = source_bytes[source_bit_idx] & 1
            decoded_byte += str(bit)

            if is_message:
                source_bit_idx += next(keyed_spacer)
                if len(decoded_byte) == BYTE_SIZE:
                    decoded_byte_chr = chr(int(decoded_byte, 2))
                    if decoded_byte_chr == END_OF_MESSAGE:
                        return result
                    result += decoded_byte_chr
                    decoded_byte = ""
            else:
                if len(decoded_byte) == BYTE_SIZE:
                    if chr(int(decoded_byte, 2)) == START_OF_MESSAGE:
                        is_message = True
                        source_bit_idx += next(keyed_spacer)
                        decoded_byte = ""
                        continue
                    decoded_byte = ""
                source_bit_idx += 1

    @check_session
    def decode(self, image_path: str, session_manager: SessionManager):
        
        self.image_path = Path(image_path)
        self.session = session_manager.get_session()
        self.user_id =  self.session["id"]        
        
        image_handler = ImageHandler(self.image_path)
        for band in image_handler.bands.keys():
            band_values = image_handler.get_band_values(band)

            header = self._get_header(band_values)

            if header:
                header_decoded = base64.b64decode(header.encode('ascii')).decode()
                bands, key = header_decoded.split('|')
                password = self._retrieve_message_lsb(band_values, key)
                print(password)
    
    @check_session
    def encode(self, image_path: str, password: str, session_manager: SessionManager):
        
        self.image_path = Path(image_path)
        self.password = password
        self.session = session_manager.get_session()
        self.user_id =  self.session["id"]
        
        image_handler = ImageHandler(self.image_path)
        band_values = {}
        if len(self.password) < image_handler.size:
            # only one band is necessary (default for passwords)
            # but the band is chosen at random
            band = choice(list(image_handler.bands.keys()))
            band_values[band] = image_handler.get_band_values(band)

            key = password_generator(10, True, True, True)

            header = self._create_header([band], key)
            message = header + START_OF_MESSAGE + self.password + END_OF_MESSAGE

            self._insert_message_lsb(message.encode(), band_values[band], key)
            print(band)
            print(band_values[band][:8])

            image_handler.replace_band(band, band_values[band])

            # print(len(bytearray(R_values)))
        else:
            # WIP
            pass
