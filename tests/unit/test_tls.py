# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TLS service unit tests."""

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

import tls

if TYPE_CHECKING:
    from pathlib import Path


class TestGetAutocertCn:
    def test_no_autocert_dir(self, tmp_path: "Path") -> None:
        """
        arrange: Define a path to a non-existent autocert directory.
        act: Call _get_autocert_cn.
        assert: An empty string is returned.
        """
        autocert_conf_dir = tmp_path / "autocert"

        result = tls._get_autocert_cn(str(autocert_conf_dir))

        assert result == ""

    def test_empty_autocert_dir(self, tmp_path: "Path") -> None:
        """
        arrange: Create an empty autocert directory.
        act: Call _get_autocert_cn.
        assert: An empty string is returned.
        """
        autocert_conf_dir = tmp_path / "autocert"
        autocert_conf_dir.mkdir()

        result = tls._get_autocert_cn(str(autocert_conf_dir))

        assert result == ""

    def test_single_config_file(self, tmp_path: "Path") -> None:
        """
        arrange: Create an autocert directory with one .ini file.
        act: Call _get_autocert_cn.
        assert: The common name is correctly extracted from the filename.
        """
        autocert_conf_dir = tmp_path / "autocert"
        autocert_conf_dir.mkdir()
        (autocert_conf_dir / "smtp.mydomain.local.ini").touch()

        result = tls._get_autocert_cn(str(autocert_conf_dir))

        assert result == "smtp.mydomain.local"

    def test_multiple_files_sorted(self, tmp_path: "Path") -> None:
        """
        arrange: Create an autocert directory with multiple files.
        act: Call _get_autocert_cn.
        assert: The common name from the first .ini file alphabetically is returned.
        """
        autocert_conf_dir = tmp_path / "autocert"
        autocert_conf_dir.mkdir()
        (autocert_conf_dir / "aaa.unrelated.file").touch()
        (autocert_conf_dir / "zzz.mydomain.local.ini").touch()
        (autocert_conf_dir / "bbb.mydomain.local.ini").touch()

        result = tls._get_autocert_cn(str(autocert_conf_dir))

        assert result == "bbb.mydomain.local"


class TestGetTlsConfigPaths:
    @pytest.mark.parametrize(
        ("dhparams_exist"),
        [
            pytest.param(False, id="no_dhparams"),
            pytest.param(True, id="with_dhparams"),
        ],
    )
    @patch("tls.subprocess.call")
    @patch("tls._get_autocert_cn", return_value="")
    def test_path_logic_without_autocert(
        self,
        _mock_get_autocert_cn: Mock,
        mock_subprocess_call: Mock,
        dhparams_exist: bool,
        tmp_path: "Path",
    ) -> None:
        """
        arrange: Given no autocert certificate, check behavior based on DH file existence.
        act: Call get_tls_config_paths.
        assert: Snakeoil paths are returned and openssl is called only when needed.
        """
        dhparams_path = tmp_path / "dhparams.pem"
        if dhparams_exist:
            dhparams_path.touch()

        result = tls.get_tls_config_paths(str(dhparams_path))

        if dhparams_exist:
            mock_subprocess_call.assert_not_called()
        else:
            mock_subprocess_call.assert_called_with(
                ["openssl", "dhparam", "-out", str(dhparams_path), "2048"]
            )

        assert result.tls_cert == "/etc/ssl/certs/ssl-cert-snakeoil.pem"
        assert result.tls_key == "/etc/ssl/private/ssl-cert-snakeoil.key"
        assert result.tls_dh_params == str(dhparams_path)

    @patch("tls.subprocess.call")
    @patch("tls._get_autocert_cn", return_value="smtp.example.com")
    @patch("tls.os.path.exists", return_value=False)
    def test_path_logic_with_autocert(
        self,
        _mock_exists: Mock,
        _mock_get_autocert_cn: Mock,
        mock_subprocess_call: Mock,
        tmp_path: "Path",
    ) -> None:
        """
        arrange: Given an autocert certificate is present and its DH file is missing.
        act: Call get_tls_config_paths.
        assert: Autocert paths are returned and openssl is called to create the DH file.
        """
        # This path is passed but will be ignored by the function's logic
        ignored_dhparams_path = str(tmp_path / "dhparams.pem")

        result = tls.get_tls_config_paths(ignored_dhparams_path)

        mock_subprocess_call.assert_called_with(
            ["openssl", "dhparam", "-out", "/etc/postfix/ssl/dhparams.pem", "2048"]
        )
        assert result.tls_cert == "/etc/postfix/ssl/smtp.example.com.crt"
        assert result.tls_key == "/etc/postfix/ssl/smtp.example.com.key"
        assert result.tls_dh_params == "/etc/postfix/ssl/dhparams.pem"
