"""Direct script entry-point compatibility tests."""

from pathlib import Path
import subprocess
import sys


def test_cli_script_can_be_imported_from_project_root():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "ioc_rejudge" / "cli.py"), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()
    assert "No module named 'ioc_rejudge'" not in result.stderr
