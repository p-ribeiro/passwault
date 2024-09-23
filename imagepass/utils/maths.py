from typing import List


def int_to_bin(int_list: List[int]) -> List[str]:
    bytes_list: List[bytes] = [bin(val) for val in int_list]
    
    return bytes_list
