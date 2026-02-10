import sys
from pathlib import Path

# Module-level portable data directory override
_portable_data_dir: Path | None = None


def set_portable_data_dir(exe_dir: Path) -> None:
    """Set the data directory to a portable path relative to the executable.

    Args:
        exe_dir: Directory where the executable lives (USB drive root).
    """
    global _portable_data_dir
    _portable_data_dir = exe_dir / "passwault-data"
    _portable_data_dir.mkdir(parents=True, exist_ok=True)


def get_data_dir() -> Path:
    """Get the application data directory, creating it if needed.

    In portable mode, returns a directory next to the executable.
    Otherwise, returns the default ~/.local/share/passwault/ path.
    """
    if _portable_data_dir is not None:
        return _portable_data_dir

    data_dir = Path.home() / ".local" / "share" / "passwault"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_executable_dir() -> Path:
    """Get the directory containing the running executable or script.

    Works for both PyInstaller bundles and normal Python invocations.
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller bundle
        return Path(sys.executable).parent
    else:
        # Running as normal Python script
        return Path(__file__).resolve().parent.parent.parent.parent
