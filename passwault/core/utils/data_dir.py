from pathlib import Path


def get_data_dir() -> Path:
    """Get the application data directory, creating it if needed."""
    data_dir = Path.home() / ".local" / "share" / "passwault"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
