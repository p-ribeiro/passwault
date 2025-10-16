
from pathlib import Path
import shutil

import test

from passwault.imagepass.embedder import Embedder


def test_encode_decode(tmp_path):
    # Copying the test image to a temp file to avoid modifying the original
    src_image = Path(__file__).parent / "assets" / "no_secrets_here.png"
    test_image = tmp_path / "sample_image.png"
    shutil.copy(src_image, test_image)
    
    # Create output directory
    output_dir = tmp_path / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create the message to hide
    message = """
    I am by birth a Genevese, and my family is one of the most distinguished of that republic.
    My ancestors had been for many years counsellors and syndics, and my father had filled several public situations with honour and reputation.
    He was respected by all who knew him for his integrity and indefatigable attention to public business.
    He passed his younger days perpetually occupied by the affairs of his country;
    a variety of circumstances had prevented his marrying early, nor was it until the decline of life that he became a husband and the father of a family.
    """
    
    # Initialize the encoder
    encoder = Embedder(test_image, output_dir)
    
    encoder.encode(message)
    output_image = output_dir / "sample_image.png"
    assert output_image.exists(), "Encoded image was not created."
    
    # Initialize the decoder
    decoder = Embedder(output_image)
    decoded_message = decoder.decode()
    assert decoded_message is not None, "Decoded message is None."
    assert message.strip() == decoded_message.strip(), "Decoded message does not match the original."
    
    
    
    
    