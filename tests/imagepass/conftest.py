import pytest
from PIL import Image


@pytest.fixture
def tmp_image_rgb(tmp_path):
    test_image_path = tmp_path / "test_rgb.png"
    Image.new("RGB", (300, 200), color=(102, 200, 235)).save(test_image_path)
    return test_image_path

@pytest.fixture
def tmp_image_rgba(tmp_path):
    test_image_path = tmp_path / "test_rgba.png"
    Image.new("RGBA", (300, 200), color=(102, 200, 235)).save(test_image_path)
    return test_image_path

@pytest.fixture
def tmp_image_rgb_jpeg(tmp_path):
    test_image_path = tmp_path / "test_rgb.jpg"
    Image.new("RGB", (300, 200), color=(102, 200, 235)).save(test_image_path, format="JPEG")
    return test_image_path

@pytest.fixture
def tmp_image_bw(tmp_path):
    test_image_path = tmp_path / "test_bw.png"
    Image.new("L", (300, 200)).save(test_image_path)
    return test_image_path

@pytest.fixture
def new_band_values():
    return [111] * (200 * 300) 