from typing import List
import binascii

def message_to_bytes(message: str) -> bytes:
    
    """Return the 8 bits representation of all characters in the string

    Returns:
        str: A string with all the bits concatenated
    """
        
    in_bytes = message.encode()        
    
    return in_bytes

if __name__ == "__main__":
    print(message_to_bytes("a"))