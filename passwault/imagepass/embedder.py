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
        self.image_handler = ImageHandler(self.image_path)
        self.password = None
        self.session = None
        self.user_id = None

        if session_manager:
            self.session = session_manager.get_session()
            self.user_id = self.session["id"] if self.session else None

    def _create_bands_bitmask(self) -> int:
        """Bitmask for R/G/B/A/L channels\n
        (b0=R, b1=G, b2=B, b3=A, b4=L)
        """
        
        
        r = "R" in self.image_handler.bands
        g = "G" in self.image_handler.bands
        b = "B" in self.image_handler.bands
        a = "A" in self.image_handler.bands
        l = "L" in self.image_handler.bands
        
        bands_bitmask = (r<<0) | (g<<1) | (b<<2) | (a << 3) | (l << 4)
        return bands_bitmask
        

    def _upack_header(self, header: bytes):
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

    def _create_header(self, key: str, msg_len: int) -> bytes:
        
        bands_bitmask = self._create_bands_bitmask()
        msg_len_bytes = msg_len.to_bytes(4, "big")


        header_struct = {
            "MARKER": '\xDE\xAD\xCA\xFE',   # 4 bytes
            "BAND_MASK": bands_bitmask,     # 1 bytes (b0=R,b1=G,b2=B,b3=A)
            "MESSAGE_LEN": msg_len_bytes,   # 4 bytes
            "ALG_ID": 1,                    # 1 byte
            "KEY": key,                     # 10 bytes
            "HEADER_CRC": 0x123456          # 4 bytes
        }

        header_fixed = struct.pack(">IBBIB", 
                              header_struct["MARKER"],
                              header_struct["BAND_MASK"],
                              header_struct["MESSAGE_LEN"],
                              header_struct["ALG_ID"],
                              header_struct["KEY"]
                        )
    
        
        # compute the CRC32
        header_crc = zlib.crc32(header_fixed).to_bytes(4, "big")
        
        final_header = header_fixed + header_crc
      
        return final_header
        

    def _get_header_bytes(self, band_values: List[int]) -> Optional[bytes]:
        def _chunks_of_eight(lst: List[int]):
            for i in range(0, len(lst), 8):
                yield lst[i : i + 8]

        MARKER = b'\xDE\xAD\xCA\xFE'
        HEADER_LEN = 14 # Header has a fixed size of 14 bytes
        
        header_bytes_buffer = b''
        
        for byte_chunk in _chunks_of_eight(band_values):
            # get a string of 0 and 1 from the LSB of the bytes list
            bits = "".join([str(value & 1) for value in byte_chunk])
            
            # convert the string to a single byte
            byte_value = int(bits, 2).to_bytes(1, "big")
            
            header_bytes_buffer += byte_value
            
            ## check marker after the first 4 bytes
            # if marker is not found, the value is not here or is corrupted
            if header_bytes_buffer[:4] != MARKER:
                return None

            if len(header_bytes_buffer) == HEADER_LEN:
                return header_bytes_buffer
            

            

            
            

    @staticmethod
    def _key_spacing_generator(key: str):
        cnt = 0
        key_size = len(key)
        while True:
            yield ord(key[cnt % key_size])
            cnt += 1

    def _insert_message_lsb(
        self,
        header: bytes,
        payload: bytes, 
        target_bytes: List[int], 
        key: str
    ) -> None:
        """In-place embedding of each bit of `source_bytes` into the least significant bit (LSB) of `target_bytes`.

        Args:
            source_bytes (bytes): the bytes to be embedded into the target.
            target_bytes (List[int]): the bytearray into which the source bytes will be embedded.
        """

        last_byte = ""
        target_lenght = len(target_bytes)
        bit_idx = 0
        
        # add header first
        for byte in header:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                last_byte += str(bit)

                if bit_idx < target_lenght:

                    if bit:
                        target_bytes[bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[bit_idx] &= ~1  # clear LSB to 0
        
                if len(last_byte) == BYTE_SIZE:
                    last_byte = ""
            
                bit_idx += 1

        # add the payload with the key spacing
        keyed_spacer = self._key_spacing_generator(key)
        for byte in payload:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                last_byte += str(bit)

                if bit_idx < target_lenght:

                    if bit:
                        target_bytes[bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[bit_idx] &= ~1  # clear LSB to 0
        
                if len(last_byte) == BYTE_SIZE:
                    last_byte = ""
            
                bit_idx += next(keyed_spacer)

    def _retrieve_message_lsb(self, source_bytes: List[int], key: str) -> Optional[str]:

        keyed_spacer = self._key_spacing_generator(key)
        source_bit_idx = 0
        decoded_byte = ""
        result = ""
        
        header = self._get_header_bytes(source_bytes)
        if not header:
            raise ValueError("Header not found")
        
        header_decoded = self._upack_header(header)
        
        message_len = header_decoded["msg_len"]

        # get message
        
        while source_bit_idx < len(source_bytes):
            bit = source_bytes[source_bit_idx] & 1
            decoded_byte += str(bit)

            source_bit_idx += next(keyed_spacer)
            
            if len(decoded_byte) == BYTE_SIZE:
                decoded_byte_chr = chr(int(decoded_byte, 2))
                result += decoded_byte_chr
                decoded_byte = ""
            if len(result) == message_len:
                return result
            

    # @check_session
    def decode(self):
        for band in self.image_handler.bands.keys():
            band_values = self.image_handler.get_band_values(band)

            header = self._get_header_bytes(band_values)

            if header:
                header_decoded = base64.b64decode(header.encode("ascii")).decode()
                bands, key = header_decoded.split("|")
                password = self._retrieve_message_lsb(band_values, key)
                print(f"The retrieved password is: {password}")

    # @check_session
    def encode(self, message: str):
        self.password = message
        
        band_values = {}
        if len(self.password) < self.image_handler.size:
            # only one band is necessary (default for passwords)
            # but the band is chosen at random
            band = choice(list(self.image_handler.bands.keys()))
            band_values[band] = self.image_handler.get_band_values(band)

            # the key is always 10 chars long
            key = password_generator(
                len=10,
                has_symbols=True,
                has_digits=True,
                has_uppercase=True
            )
    
            header = self._create_header(key, len(message))
            
            msg_crc = zlib.crc32(message.encode()).to_bytes(4, 'big')
            
            payload = header + message.encode() + msg_crc 
            
            self._insert_message_lsb(payload, band_values[band], key)

            self.image_handler.replace_band(band, band_values[band])
            
        else:
            # WIP
            pass
