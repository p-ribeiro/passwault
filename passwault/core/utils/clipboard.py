"""Cross-platform clipboard utilities for Passwault.

This module provides clipboard functionality that works across
Windows, macOS, Linux, and WSL environments.
"""

import platform
import shutil
import subprocess

from passwault.core.utils.local_types import ClipboardError
from passwault.core.utils.logger import Logger


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard.

    Attempts to copy text using platform-appropriate clipboard tool.

    Args:
        text: The text to copy to clipboard

    Returns:
        True if copy succeeded, False if no clipboard tool available

    Raises:
        ClipboardError: If clipboard command fails
    """
    system = platform.system()

    try:
        # WSL detection (Linux but has clip.exe)
        if system == "Linux" and shutil.which("clip.exe"):
            subprocess.run(
                ["clip.exe"],
                input=text.encode("utf-16-le"),
                check=True,
            )
            return True

        elif system == "Darwin":  # macOS
            subprocess.run(
                ["pbcopy"],
                input=text.encode(),
                check=True,
            )
            return True

        elif system == "Linux":
            if shutil.which("xclip"):
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode(),
                    check=True,
                )
                return True
            elif shutil.which("xsel"):
                subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode(),
                    check=True,
                )
                return True
            else:
                return False

        elif system == "Windows":
            subprocess.run(
                ["clip"],
                input=text.encode("utf-16-le"),
                shell=True,
                check=True,
            )
            return True

        else:
            return False

    except subprocess.CalledProcessError as e:
        raise ClipboardError(f"Clipboard command failed: {e}")
    except Exception as e:
        raise ClipboardError(f"Unexpected clipboard error: {e}")


def try_copy_to_clipboard(text: str) -> bool:
    """Attempt to copy text to clipboard, logging result.

    Non-blocking wrapper that logs success/failure instead of raising.

    Args:
        text: The text to copy to clipboard

    Returns:
        True if copy succeeded, False otherwise
    """
    try:
        if copy_to_clipboard(text):
            Logger.info("Password copied to clipboard")
            return True
        else:
            Logger.warning("No clipboard tool available - password not copied")
            return False
    except ClipboardError as e:
        Logger.warning(f"Could not copy to clipboard: {e}")
        return False
