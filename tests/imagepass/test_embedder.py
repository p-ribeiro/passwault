from passwault.imagepass.embedder import Embedder
from passwault.imagepass.utils.utils import key_generator

MESSAGE = "This is my message to the world, but it should be hidden"


def test_create_bands_byte_rgb(tmp_image_rgb, session_manager):
    embedder = Embedder(tmp_image_rgb, session_manager=session_manager)
    bands_bitmask = embedder._create_bands_bitmask()

    assert (bands_bitmask >> 0) & 1 == 1
    assert (bands_bitmask >> 1) & 1 == 1
    assert (bands_bitmask >> 2) & 1 == 1
    assert (bands_bitmask >> 3) & 1 == 0
    assert (bands_bitmask >> 4) & 1 == 0


def test_create_bands_byte_rgba(tmp_image_rgba, session_manager):
    embedder = Embedder(tmp_image_rgba, session_manager=session_manager)
    bands_bitmask = embedder._create_bands_bitmask()

    assert (bands_bitmask >> 0) & 1 == 1
    assert (bands_bitmask >> 1) & 1 == 1
    assert (bands_bitmask >> 2) & 1 == 1
    assert (bands_bitmask >> 3) & 1 == 1
    assert (bands_bitmask >> 4) & 1 == 0


def test_create_bands_byte_bw(tmp_image_bw, session_manager):
    embedder = Embedder(tmp_image_bw, session_manager=session_manager)
    bands_bitmask = embedder._create_bands_bitmask()

    assert (bands_bitmask >> 0) & 1 == 0
    assert (bands_bitmask >> 1) & 1 == 0
    assert (bands_bitmask >> 2) & 1 == 0
    assert (bands_bitmask >> 3) & 1 == 0
    assert (bands_bitmask >> 4) & 1 == 1


def test_header_size(tmp_image_rgb, session_manager):
    # header must be a fixed 24 bytes

    embedder = Embedder(tmp_image_rgb, session_manager=session_manager)
    key = key_generator()
    header = embedder._create_header(key, len(MESSAGE))
    assert len(header) == 24


def test_unpack_header(tmp_image_rgb, session_manager):
    embedder = Embedder(tmp_image_rgb, session_manager=session_manager)

    key = key_generator()
    header_bytes = embedder._create_header(key, len(MESSAGE))

    header = embedder._unpack_header(header_bytes)
    assert header.key.decode() == key
    assert header.band_mask == int(0b0000111)
    assert header.message_len == len(MESSAGE)
    assert header.marker == 0xDEADCAFE


def test_insert_header_lsb(tmp_image_rgb, session_manager):
    embedder = Embedder(tmp_image_rgb, session_manager=session_manager)
    test_bytes = [255] * 60_000
    key = key_generator()

    # header has 24 * 8 = 192
    header = embedder._create_header(key, len(MESSAGE))

    payload = header + MESSAGE.encode()

    embedder._insert_message_lsb(header, payload, test_bytes, key)

    # verify the marker (0xDEADCAFE) was correctly embedded in the first 32 LSBs
    marker_bits = "".join(str(test_bytes[i] & 1) for i in range(32))
    marker_value = int(marker_bits, 2)
    assert marker_value == 0xDEADCAFE
