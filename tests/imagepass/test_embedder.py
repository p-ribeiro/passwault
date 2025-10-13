from click import BadArgumentUsage
from passwault.imagepass.embedder import Embedder

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
    embedder = Embedder(tmp_image_rgb)
    key = "123TESTKEY" # 10 bytes
    
    header = embedder._create_header(key)
    assert len(header) == 25

def test_unpack_header(tmp_image_rgb):
    embedder = Embedder(tmp_image_rgb)
    key = "Th1sIsMy|Test|Key"
    header = embedder._create_header(key)
    
    header_read = embedder._upack_header(header)
    
    print(header_read)
    assert header_read["key"].decode() == key
    
    
    
    
