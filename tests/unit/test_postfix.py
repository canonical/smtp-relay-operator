# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix service unit tests."""

from unittest import mock
from typing import TYPE_CHECKING


from reactive import utils, postfix  # NOQA: E402

if TYPE_CHECKING:
    from pathlib import Path


@mock.patch("subprocess.call")
@mock.patch("reactive.postfix.os.utime")
@mock.patch("reactive.postfix.utils.write_file")
class TestCreateUpdateMap:

    def test_pmfname_file_not_exists(self, write_file, os_utime, call, tmp_path: "Path") -> None:
        # Given
        write_file.return_value = True
        non_existing_file_path = tmp_path / "pmfname"
        postmap = f"hash:{non_existing_file_path}"

        # When
        result = postfix._create_update_map("contents", postmap)

        # Then
        os_utime.assert_called_once_with(str(non_existing_file_path), None)
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(non_existing_file_path),
        )
        assert result is True

    def test_pmfname_file_exists_no_change(
        self, write_file, os_utime, call, tmp_path: "Path"
    ) -> None:
        # Given
        write_file.return_value = False
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # When
        result = postfix._create_update_map("contents", postmap)

        # Then
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        assert result is False

    def test_pmfname_file_exists_change_hash_type(
        self, write_file, os_utime, call, tmp_path: "Path"
    ) -> None:
        # Given
        write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # When
        result = postfix._create_update_map("contents", postmap)

        # Then
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        call.asset_called_once_with(["postmap", postmap])
        assert result is True

    def test_pmfname_file_exists_change_not_hash_type(
        self, write_file, os_utime, call, tmp_path: "Path"
    ) -> None:
        # Given
        write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"cidr:{exising_file_path}"

        # When
        result = postfix._create_update_map("contents", postmap)

        # Then
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        call.assert_not_called()
        assert result is True
