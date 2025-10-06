"""Tests package-level imports."""

from pathlib import Path
import sys
import importlib


def test_package_exposes_ipfinderapp():
    """Ensure IPFinderApp is importable from the package root."""
    project_root = Path(__file__).resolve().parents[1]
    src_path = project_root / "src"
    src_str = str(src_path)

    if src_str not in sys.path:
        sys.path.insert(0, src_str)

    package = importlib.import_module("IP_Locator")

    assert hasattr(package, "IPFinderApp"), "IPFinderApp should be available at package root"
