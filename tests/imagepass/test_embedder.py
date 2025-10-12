from passwault.imagepass.embedder import Embedder


def test_header_size(tmp_image_rgb):
    embedder = Embedder(tmp_image_rgb)
    key = "123TESTKEY" # 10 bytes
    
    header = embedder._create_header(["R", "G", "B"], key)
    assert len(header) == 25

def test_read_header(tmp_image_rgb):
    embedder = Embedder(tmp_image_rgb)
    key = "Th1sIsMy|Test|Key"
    header = embedder._create_header(["R", "G","B"], key)
    
    header_read = embedder._read_header(header)
    
    print(header_read)
    assert header_read["key"].decode() == key
    
    
    
    
