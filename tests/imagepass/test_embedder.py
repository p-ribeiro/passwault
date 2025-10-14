from click import BadArgumentUsage
from passwault.imagepass.embedder import Embedder
from passwault.imagepass.utils.utils import key_generator

def test_create_bands_byte_rgb(tmp_image_rgb):
    embedder = Embedder(tmp_image_rgb)
    bands_bitmask = embedder._create_bands_bitmask()
    
    assert (bands_bitmask >> 0) & 1 == 1
    assert (bands_bitmask >> 1) & 1 == 1
    assert (bands_bitmask >> 2) & 1 == 1
    assert (bands_bitmask >> 3) & 1 == 0
    assert (bands_bitmask >> 4) & 1 == 0

    
def test_create_bands_byte_rgba(tmp_image_rgba):
    embedder = Embedder(tmp_image_rgba)
    bands_bitmask = embedder._create_bands_bitmask()
    
    assert (bands_bitmask >> 0) & 1 == 1
    assert (bands_bitmask >> 1) & 1 == 1
    assert (bands_bitmask >> 2) & 1 == 1
    assert (bands_bitmask >> 3) & 1 == 1
    assert (bands_bitmask >> 4) & 1 == 0

def test_create_bands_byte_bw(tmp_image_bw):
    embedder = Embedder(tmp_image_bw)
    bands_bitmask = embedder._create_bands_bitmask()
    
    assert (bands_bitmask >> 0) & 1 == 0
    assert (bands_bitmask >> 1) & 1 == 0
    assert (bands_bitmask >> 2) & 1 == 0
    assert (bands_bitmask >> 3) & 1 == 0
    assert (bands_bitmask >> 4) & 1 == 1


def test_header_size(tmp_image_rgb):
    # header must be a fixed 24 bytes
    
    embedder = Embedder(tmp_image_rgb)
    key = "123TESTKEY" # 10 bytes
    message= "This is my message to the world, but it should be hidden"
    header = embedder._create_header(key, len(message))
    assert len(header) == 24

def test_unpack_header(tmp_image_rgb):
    embedder = Embedder(tmp_image_rgb)
    
    key = key_generator()
    message= "This is my message to the world, but it should be hidden"
    header_bytes = embedder._create_header(key, len(message))
    
    header = embedder._unpack_header(header_bytes)
    assert header.key.decode() == key
    assert header.band_mask == int(0b0000111)
    assert header.message_len == len(message)
    assert header.marker == 0xDEADCAFE
    
    

