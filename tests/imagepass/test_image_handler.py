from passwault.imagepass.utils.image_handler import ImageHandler
import pytest


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
    assert bands["R"] == 0
    assert bands["G"] == 1
    assert bands["B"] == 2


def test_get_image_bands_RGBA(tmp_image_rgba):
    image_handler = ImageHandler(tmp_image_rgba)
    bands = image_handler._get_image_bands()

    assert ["R", "G", "B", "A"] == list(bands.keys())
    assert bands["R"] == 0
    assert bands["G"] == 1
    assert bands["B"] == 2
    assert bands["A"] == 3


def test_get_image_bands_bw(tmp_image_bw):
    image_handler = ImageHandler(tmp_image_bw)
    bands = image_handler._get_image_bands()

    assert ["L"] == list(bands.keys())
    assert bands["L"] == 0


def test_band_values(tmp_image_rgb):
    image_handler = ImageHandler(tmp_image_rgb)

    red_band_values = image_handler.get_band_values("R")
    green_band_values = image_handler.get_band_values("G")
    blue_band_values = image_handler.get_band_values("B")

    assert [102, 102] == red_band_values[:2]
    assert [200, 200] == green_band_values[:2]
    assert [235, 235] == blue_band_values[:2]

    assert 200 * 300 == len(red_band_values)


def test_replace_band_R(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    result_image = image_handler.replace_band("R", new_band_values)

    assert result_image is not None

    red_band_values = result_image.getdata(0)
    assert 111 == red_band_values[10]


def test_replace_band_G(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    result_image = image_handler.replace_band("G", new_band_values)

    assert result_image is not None

    green_band_values = result_image.getdata(1)
    assert 111 == green_band_values[10]


def test_replace_band_B(tmp_image_rgb, new_band_values):
    image_handler = ImageHandler(tmp_image_rgb)
    result_image = image_handler.replace_band("B", new_band_values)

    assert result_image is not None

    blue_band_values = result_image.getdata(2)
    assert 111 == blue_band_values[10]


def test_replace_band_A(tmp_image_rgba, new_band_values):
    image_handler = ImageHandler(tmp_image_rgba)
    result_image = image_handler.replace_band("A", new_band_values)

    assert result_image is not None

    alpha_band_values = result_image.getdata(3)
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


def test_save_image_to_file(tmp_image_rgb, tmp_path, new_band_values):
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    image_handler = ImageHandler(tmp_image_rgb, output_dir)

    result_image = image_handler.replace_band("R", new_band_values)
    assert result_image is not None

    # asserting that the file does not exist yet
    assert not (output_dir / "test_rgb.png").exists()

    image_handler.save_image_to_file(result_image)
    assert (output_dir / "test_rgb.png").exists()
