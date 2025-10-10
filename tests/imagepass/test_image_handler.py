from email.mime import image
import tempfile
from PIL import Image
from unittest import TestCase
import pytest

from passwault.imagepass.utils import image_handler
from passwault.imagepass.utils.image_handler import ImageHandler

@pytest.fixture
def temp_image(tmp_path):
    test_image_path = tmp_path / "test.png"
    Image.new("RGB", (300, 200), color=(102, 200, 235)).save(test_image_path)
    return test_image_path

def test_get_image_dimensions(temp_image):
    image_handler = ImageHandler(temp_image)
    w, h = image_handler._get_image_dimensions()
    
    assert temp_image.exists()
    assert w == 300
    assert h == 200

def test_get_image_bands_RGB(temp_image):
    image_handler = ImageHandler(temp_image)
    bands = image_handler._get_image_bands()
    
    assert ["R", "G", "B"] == list(bands.keys())
    assert bands['R'] == 0
    assert bands['G'] == 1
    assert bands['B'] == 2
    
def test_get_image_bands_RGBA(tmp_path):
    test_image_path = tmp_path / "test.png"
    Image.new("RGBA", (300, 200), color=(102, 200, 235)).save(test_image_path)
    
    image_handler = ImageHandler(test_image_path)
    bands = image_handler._get_image_bands()
    
    assert ["R", "G", "B", "A"] == list(bands.keys())
    assert bands['R'] == 0
    assert bands['G'] == 1
    assert bands['B'] == 2
    assert bands["A"] == 3

def test_get_iamge_bands_bw(tmp_path):
    test_image_path = tmp_path / "test.png"
    Image.new("L", (300, 200)).save(test_image_path)
    
    image_handler = ImageHandler(test_image_path)
    bands = image_handler._get_image_bands()
    
    assert ["L"] == list(bands.keys())
    assert bands['L'] == 0

def test_band_values(temp_image):
    image_handler = ImageHandler(temp_image)
    
    red_band_values = image_handler.get_band_values("R")
    green_band_values = image_handler.get_band_values("G")
    blue_band_values = image_handler.get_band_values("B")
    
    assert [102, 102] == red_band_values[:2]
    assert [200, 200] == green_band_values[:2]
    assert [235, 235] == blue_band_values[:2]
    
    assert 200*300 == len(red_band_values)


def test_replace_band(temp_image):
    new_band_values = [111] * (200 * 300)
    image_handler = ImageHandler(temp_image)
    
    image_handler.replace_band("G", new_band_values)
    
    green_band_values = image_handler.get_band_values("G")
    
    # print(image_handler.image_suffix)
    
    assert 111 == green_band_values[10]