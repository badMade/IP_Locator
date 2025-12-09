"""Tests for package installation helper functions."""

import builtins
import unittest
from unittest.mock import patch

from ip_location_finder import install_and_log_packages


class TestInstallAndLogPackages(unittest.TestCase):
    """Validate installation logic for required packages."""

    def test_skips_pip_installation_for_tkinter(self) -> None:
        """Ensure standard library modules do not trigger pip installation."""

        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):  # type: ignore[override]
            if name == 'tkinter':
                raise ImportError("No module named 'tkinter'")
            return original_import(name, *args, **kwargs)

        with patch('ip_location_finder.subprocess.check_call') as mock_check_call, \
                patch('ip_location_finder.logging.warning') as mock_warning, \
                patch('builtins.__import__', side_effect=fake_import):
            install_and_log_packages(['tkinter'])

        mock_check_call.assert_not_called()
        mock_warning.assert_called_once()
        warning_args = mock_warning.call_args[0]
        assert "Standard library module" in warning_args[0]
        assert warning_args[1] == 'tkinter'


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
