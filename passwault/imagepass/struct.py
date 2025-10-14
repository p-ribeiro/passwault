from dataclasses import dataclass


@dataclass
class Header:
    marker:         int     # 4 bytes
    band_mask:      int     # 1 byte
    message_len:    int     # 4 bytes
    algo_id:        int     # 1 bytes
    key:            bytes   # 10 bytes