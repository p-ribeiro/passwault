from pathlib import Path

from .utils.image_handler import ImageHandler


class Encoder:
    def __init__(self, image_path: str, password: str) -> None:
        self.image_path = Path(image_path)
        self.password = password
        ...

    def _embbed_message_lsb(self, source_bytes: bytes, target_bytes: bytearray):
        target_lenght = len(target_bytes)
        source_bit_idx = 0
        
        for byte in source_bytes:
            for bit_pos in range(7, -1, -1):
                bit = byte >> bit_pos & 1
                
                if source_bit_idx < target_lenght:
                    
                    if bit:
                        target_bytes[source_bit_idx] |= 1 # set LSB to 1
                    else:
                        target_bytes[source_bit_idx] &= ~1 # clear LSB to 0
                    
                source_bit_idx += 1
        
        


    def encode(self):
        image_handler = ImageHandler(self.image_path)
        R_values = image_handler.get_band_values("R")
        
        data = bytearray(16)
       
        print(data[:16]) 
        self._embbed_message_lsb(b'at', data)
        print(data[:16])
        
        # print(len(bytearray(R_values)))
