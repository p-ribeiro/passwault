import argparse
from .embedder import Embedder
from .utils import verifier

VALID_IMAGE_EXTENSIONS = [".jpg", ".png", ".gif", ".jpeg", ".tiff", ".bmp"]


def main():
    parser = argparse.ArgumentParser(
        prog="ImagePass",
        description="Insert an image path and a password to encode the password into the image",
    )
    parser.add_argument(
        "option", choices=["encode", "decode"], help="the operation to be done"
    )
    parser.add_argument("image_path", help="the image to encode or decode the password")
    parser.add_argument("-p", "--password", help="the password to be encoded")
    args = parser.parse_args()

    if not verifier.verify_image_path(args.image_path):
        raise ValueError("ERROR: The path is not valid")

    if verifier.get_file_extension(args.image_path) not in VALID_IMAGE_EXTENSIONS:
        raise ValueError(
            f"ERROR: not a valid image extension. VALID EXTENSIONS: {' '.join(VALID_IMAGE_EXTENSIONS)}"
        )

    embedder = Embedder(image_path=args.image_path)

    if args.option == "encode":
        if not args.password:
            raise ValueError("ERROR: You need to insert the password to be encoded")
        embedder.encode(args.password)
    else:
        embedder.decode()


if __name__ == "__main__":
    try:
        main()
    except ValueError as ve:
        print(ve.__str__())
