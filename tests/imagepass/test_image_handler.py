from hmac import new
import pytest
from passwault.imagepass.utils.image_handler import ImageHandler


def test_get_image_dimensions(tmp_image_rgb):
    image_handler = ImageHandler(tmp_image_rgb)
    w, h = image_handler._get_image_dimensions()
    
    assert tmp_image_rgb.exists()
    assert w == 300
    assert h == 200

def test_get_image_bands_RGB(tmp_image_rgb):
    image_handler = ImageHandler(tmp_image_rgb)
    bands = image_handler._get_image_bands()
    
    assert ["R", "G", "B"] == list(bands.keys())
    assert bands['R'] == 0
    assert bands['G'] == 1
    assert bands['B'] == 2
    
def test_get_image_bands_RGBA(tmp_image_rgba):
    image_handler = ImageHandler(tmp_image_rgba)
    bands = image_handler._get_image_bands()
    
    assert ["R", "G", "B", "A"] == list(bands.keys())
    assert bands['R'] == 0
    assert bands['G'] == 1
    assert bands['B'] == 2
    assert bands["A"] == 3

def test_get_iamge_bands_bw(tmp_image_bw):
    image_handler = ImageHandler(tmp_image_bw)
    bands = image_handler._get_image_bands()
    
    assert ["L"] == list(bands.keys())
    assert bands['L'] == 0

def test_band_values(tmp_image_rgb):
    image_handler = ImageHandler(tmp_image_rgb)
    
    red_band_values = image_handler.get_band_values("R")
    green_band_values = image_handler.get_band_values("G")
    blue_band_values = image_handler.get_band_values("B")
    
    assert [102, 102] == red_band_values[:2]
    assert [200, 200] == green_band_values[:2]
    assert [235, 235] == blue_band_values[:2]
    
    assert 200*300 == len(red_band_values)


def test_replace_band_R(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    image_handler.replace_band("R", new_band_values)
    
    red_band_values = image_handler.get_band_values("R")
    
    assert 111 == red_band_values[10]

def test_replace_band_G(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    image_handler.replace_band("G", new_band_values)
    
    green_band_values = image_handler.get_band_values("G")
    
    assert 111 == green_band_values[10]

def test_replace_band_B(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    image_handler.replace_band("B", new_band_values)
    
    blue_band_values = image_handler.get_band_values("B")
    
    assert 111 == blue_band_values[10]

def test_replace_band_A(tmp_image_rgba, new_band_values):
    image_handler = ImageHandler(tmp_image_rgba)
    image_handler.replace_band("A", new_band_values)
    
    alpha_band_values = image_handler.get_band_values("A")
    
    assert 111 == alpha_band_values[10]

def test_replace_band_invalid_band_value(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)

    with pytest.raises(ValueError):
        image_handler.replace_band("A", new_band_values)

def test_replace_band_raise_exception(tmp_image_rgb_jpeg, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb_jpeg)

    # expect a TypeError to be raised
    with pytest.raises(TypeError):
        image_handler.replace_band("G", new_band_values)

 
         
    