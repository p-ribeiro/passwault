import base64
from pathlib import Path
from random import choice
import struct
from typing import List, Optional
import zlib

from passwault.core.utils.session_manager import SessionManager
from passwault.imagepass.utils.utils import password_generator

from .utils.image_handler import ImageHandler

START_OF_HEADER = chr(1)
START_OF_MESSAGE = chr(2)
END_OF_MESSAGE = chr(3)
BYTE_SIZE = 8


class Embedder:
    def __init__(
        self, image_path: str, session_manager: Optional[SessionManager] = None
    ) -> None:
        self.image_path = Path(image_path)
        self.password = None
        self.session = None
        self.user_id = None

        if session_manager:
            self.session = session_manager.get_session()
            self.user_id = self.session["id"] if self.session else None

    def _read_header(self, header: bytes):
        marker, band_mask, key_len, msg_len, algo = struct.unpack(">IBBIB", header[:11])
        
        key = header[11 : 11+key_len]
        header_crc_stored = header[11+key_len : 11+key_len+4]
        
        # validate CRC
        header_without_crc = header[:11+key_len]
        header_crc_calc = zlib.crc32(header_without_crc).to_bytes(4, "big")
        if header_crc_calc != header_crc_stored:
            raise ValueError("Header CRC mismatch!")
        
        return {
            "marker": marker,
            "band_mask": band_mask,
            "key": key,
            "msg_len": msg_len,
            "algo": algo
        }

    def _create_header(self, bands: list[str], key: str) -> bytes:
        
        # bands == 0b00000001
        ## creating the band mask
        r = "R" in bands
        g = "G" in bands
        b = "B" in bands
        a = "A" in bands
        bands_byte = (r<<0) | (g<<1) | (b<<2) | (a << 3)
        
        
        header_struct = {
            "MARKER": 0xDEADCAFE,       # 4 bytes
            "BAND_MASK": bands_byte,    # 1 bytes (b0=R,b1=G,b2=B,b3=A)
            "KEY_LEN": len(key),        # 1 byte
            "MESSAGE_LEN": 10,          # 4 bytes
            "ALG_ID": 1,                # 1 byte
            "KEY": key,        # KEY_LEN bytes
            "HEADER_CRC": 0x123456      # 4 bytes
        }

        header_fixed = struct.pack(">IBBIB", 
                              header_struct["MARKER"],
                              header_struct["BAND_MASK"],
                              header_struct["KEY_LEN"],
                              header_struct["MESSAGE_LEN"],
                              header_struct["ALG_ID"]
                        )
        
        header_without_crc = header_fixed + header_struct["KEY"].encode()
        
        # compute the CRC32
        header_crc = zlib.crc32(header_without_crc).to_bytes(4, "big")
        
        final_header = header_without_crc + header_crc
        
      
        return final_header
        
        
        # # header format
        # # <band>[-<band>]|<key>
        # header = "-".join(bands) + "|" + key

        # return START_OF_HEADER + base64.b64encode(header.encode()).decode("ascii")

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
                print(header)
                return header

            header += encoded_byte_chr

    @staticmethod
    def _key_spacing_generator(key: str):
        cnt = 0
        key_size = len(key)
        while True:
            yield ord(key[cnt % key_size])
            cnt += 1

    def _insert_message_lsb(
        self, source_bytes: bytes, target_bytes: List[int], key: str
    ) -> None:
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

    def _retrieve_message_lsb(self, source_bytes: List[int], key: str) -> Optional[str]:

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

    # @check_session
    def decode(self):
        image_handler = ImageHandler(self.image_path)
        for band in image_handler.bands.keys():
            band_values = image_handler.get_band_values(band)

            header = self._get_header(band_values)

            if header:
                header_decoded = base64.b64decode(header.encode("ascii")).decode()
                bands, key = header_decoded.split("|")
                password = self._retrieve_message_lsb(band_values, key)
                print(f"The retrieved password is: {password}")

    # @check_session
    def encode(self, password: str):
        self.password = password
        
        image_handler = ImageHandler(self.image_path)
        band_values = {}
        if len(self.password) < image_handler.size:
            # only one band is necessary (default for passwords)
            # but the band is chosen at random
            band = choice(list(image_handler.bands.keys()))
            band_values[band] = image_handler.get_band_values(band)

            key = password_generator(
                len=10, has_symbols=True, has_digits=True, has_uppercase=True
            )

            header = self._create_header([band], key)
            message = header + START_OF_MESSAGE + self.password + END_OF_MESSAGE

            self._insert_message_lsb(message.encode(), band_values[band], key)

            image_handler.replace_band(band, band_values[band])
            
        else:
            # WIP
            pass
