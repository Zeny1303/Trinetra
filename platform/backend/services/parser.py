import json
from pathlib import Path


def read_stats(stats_path: str) -> dict:
    """Open stats.json and return its contents as a dictionary."""
    with open(stats_path, "r", encoding="utf-8") as f:
        return json.load(f)


# Alias for backward compatibility with main.py
def load_stats(stats_path: Path) -> dict:
    return read_stats(str(stats_path))
