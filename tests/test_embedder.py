from base64 import b64encode

import pytest

from imagepass.embedder import Embedder


class Test_Embedder:
    embedder = Embedder('fake_path')

    def test_create_header_all_bands(self):
        bands = ['R', 'G', 'B']
        key = "keytest"

        expected_output = chr(1) + b64encode('R-G-B|keytest'.encode()).decode('ascii')

        assert self.embedder._create_header(bands, key) == expected_output

    def test_create_header_two_bands(self):
        bands = ['G', 'B']
        key = "keytest"

        expected_output = chr(1) + b64encode('G-B|keytest'.encode()).decode('ascii')

        assert self.embedder._create_header(bands, key) == expected_output

    def test_create_header_one_band(self):
        bands = ['B']
        key = "keytest"

        expected_output = chr(1) + b64encode('B|keytest'.encode()).decode('ascii')

        assert self.embedder._create_header(bands, key) == expected_output

    def test_insert_message_lsb(self):

        source_bytes = (chr(2) + chr(124)).encode()  # 124 = 0b01111100
        key = chr(1) + chr(2)  # 1-2 spacing
        target_bytes = [0] * 20
        expected_result = [0, 0, 0, 0, 0, 0, 1, 0] + [0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0]

        self.embedder._insert_message_lsb(source_bytes, target_bytes, key)

        assert target_bytes == expected_result
