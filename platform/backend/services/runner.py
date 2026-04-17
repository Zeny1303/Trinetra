import subprocess
from pathlib import Path

BINARY_PATH = Path("../../engine/dpi_engine.exe")


def run_engine(input_path: str, output_path: str, stats_path: str) -> bool:
    """
    Run the DPI engine binary against a PCAP file.

    Args:
        input_path:  Path to the input .pcap file.
        output_path: Path where the output .pcap will be written.
        stats_path:  Path where stats.json will be written.

    Returns:
        True if the binary ran successfully and stats.json exists.

    Raises:
        FileNotFoundError: if the binary or stats.json is missing.
        RuntimeError: if the binary exits with a non-zero return code.
    """
    if not BINARY_PATH.exists():
        raise FileNotFoundError(f"Binary not found: {BINARY_PATH}")

    cmd = [str(BINARY_PATH), input_path, output_path, stats_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except OSError as e:
        raise RuntimeError(f"Failed to launch binary: {e}") from e

    if result.returncode != 0:
        raise RuntimeError(
            f"Binary exited with code {result.returncode}.\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )

    if not Path(stats_path).exists():
        raise FileNotFoundError(
            f"Binary succeeded but stats.json was not produced at: {stats_path}"
        )

    return True


# Kept for internal use by main.py
def run_analysis(input_pcap: Path, output_pcap: Path, stats_json: Path) -> None:
    run_engine(str(input_pcap), str(output_pcap), str(stats_json))
