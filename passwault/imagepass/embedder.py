import base64
from pathlib import Path
from random import choice
import struct
from typing import Any, List, Optional, Union
import zlib

from passwault.core.utils.session_manager import SessionManager
from passwault.imagepass import config
from passwault.imagepass.struct import Header
from passwault.imagepass.utils.utils import key_generator
from passwault.imagepass.utils.image_handler import ImageHandler



class Embedder:
    def __init__(
        self,
        image_path: Union[Path, str],
        output_dir: Optional[Union[Path, str]] = None,
        session_manager: Optional[SessionManager] = None
    ) -> None:
        self.image_path = image_path if isinstance(image_path, Path) else Path(image_path)
        self.output_dir = output_dir if isinstance(output_dir, Path) or output_dir is None else Path(output_dir)
        self.image_handler = ImageHandler(self.image_path, self.output_dir)
        self.message = None
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
        

    def _unpack_header(self, header: bytes) -> Header:
        marker, band_mask, msg_len, algo, key = struct.unpack(">IBIB10s", header[:config.HEADER_LEN - 4])
        
        header_crc_stored = header[config.HEADER_LEN - 4 : config.HEADER_LEN]
        
        # validate CRC
        header_without_crc = header[:config.HEADER_LEN - 4]
        header_crc_calc = zlib.crc32(header_without_crc).to_bytes(4, "big")
        if header_crc_calc != header_crc_stored:
            raise ValueError("Header CRC mismatch!")
        
        
        
        return Header(
            marker=marker,
            band_mask=band_mask,
            message_len=msg_len,
            algo_id = algo,
            key=key
        )

    def _create_header(self, key: str, msg_len: int) -> bytes:
        
        header: Header = Header(
            marker=config.MARKER,
            band_mask=self._create_bands_bitmask(),
            message_len=msg_len,
            algo_id=1,
            key=key.encode()
        )

        # packing the header dataclass into 20 bytes
        header_fixed = struct.pack(">IBIB10s", 
                            header.marker,
                            header.band_mask,
                            header.message_len,
                            header.algo_id,
                            header.key
                        )
    
        
        # compute the CRC32
        header_crc = zlib.crc32(header_fixed).to_bytes(4, "big")
        
        # 24 bytes
        final_header = header_fixed + header_crc
      
        return final_header
        

    def _get_header_bytes(self, band_values: List[int]) -> Optional[bytes]:
        def _chunks_of_eight(lst: List[int]):
            for i in range(0, len(lst), 8):
                yield lst[i : i + 8]

        header_bytes_buffer = b''
        
        for byte_chunk in _chunks_of_eight(band_values):
            # get a string of 0 and 1 from the LSB of the bytes list
            bits = "".join([str(value & 1) for value in byte_chunk])
            
            # convert the string to a single byte
            byte_value = int(bits, 2).to_bytes(1, "big")
            
            header_bytes_buffer += byte_value
            
            ## check marker after the first 4 bytes
            # if marker is not found, the value is not here or is corrupted
            if len(header_bytes_buffer) == 4:
                header_marker_int = int.from_bytes(header_bytes_buffer[:4], "big")
                if header_marker_int != config.MARKER:
                    return None

            if len(header_bytes_buffer) == config.HEADER_LEN:
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

        target_lenght = len(target_bytes)
        bit_idx = 0
        
        # add header first
        for byte in header:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                
                if bit_idx < target_lenght:

                    if bit:
                        target_bytes[bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[bit_idx] &= ~1  # clear LSB to 0
            
                bit_idx += 1

        ##########################################################
        # starting bit_idx from 192 (24 * 8)
        # add the payload with the key spacing
        keyed_spacer = self._key_spacing_generator(key)
        for byte in payload:
            # breaking the byte into bits to add to LSB of target
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1

                if bit_idx < target_lenght:
                    if bit:
                        target_bytes[bit_idx] |= 1  # set LSB to 1
                    else:
                        target_bytes[bit_idx] &= ~1  # clear LSB to 0
                
                bit_idx += next(keyed_spacer)

                

    def _retrieve_message_lsb(self,
                              source_bytes: List[int],
                              key: str,
                              msg_len: int
                            ) -> Optional[str]:

        keyed_spacer = self._key_spacing_generator(key)
        source_bit_idx = config.HEADER_LEN * config.BYTE_SIZE
        decoded_byte = ""
        result = ""
        
        # get message
        while source_bit_idx < len(source_bytes):
            bit = source_bytes[source_bit_idx] & 1
            decoded_byte += str(bit)
            
            if len(decoded_byte) == config.BYTE_SIZE:
                decoded_byte_chr = chr(int(decoded_byte, 2))
                result += decoded_byte_chr
                decoded_byte = ""
                
            if len(result) == msg_len:
                return result
            
            source_bit_idx += next(keyed_spacer)
            

    # @check_session
    def decode(self) -> Optional[str]:
        for band in self.image_handler.bands.keys():
            band_values = self.image_handler.get_band_values(band)

            header_bytes = self._get_header_bytes(band_values)

            if header_bytes:
                header = self._unpack_header(header_bytes)
                message = self._retrieve_message_lsb(
                    band_values,
                    header.key.decode(),
                    header.message_len
                )
                return message

        return None
                
                

    # @check_session
    def encode(self, message: str):
        self.message = message
        
        band_values = {}
        if len(self.message) < self.image_handler.size:
            # only one band is necessary (default for passwords)
            # but the band is chosen at random
            band = choice(list(self.image_handler.bands.keys()))
            band_values[band] = self.image_handler.get_band_values(band)

            # the key is always 10 chars long
            key = key_generator()
    
            header = self._create_header(key, len(message))
            msg_crc = zlib.crc32(message.encode()).to_bytes(4, 'big')
            payload = message.encode() + msg_crc 
            
            self._insert_message_lsb(header, payload, band_values[band], key)

            result_image = self.image_handler.replace_band(band, band_values[band])
            
            if result_image:
                self.image_handler.save_image_to_file(result_image)
        else:
            # WIP
            pass
