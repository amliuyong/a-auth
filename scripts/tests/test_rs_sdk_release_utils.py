import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.rs_sdk_release_utils import canonical_pypi_name, read_npm_token


class ReleaseIdentityTests(unittest.TestCase):
    def test_pypi_aliases_identify_the_same_project(self):
        for name in ["agent_auth_rs", "agent-auth-rs", "Agent.Auth.Rs", "agent__auth--rs"]:
            self.assertEqual(canonical_pypi_name(name), "agent-auth-rs")
        self.assertNotEqual(canonical_pypi_name("agent_auth"), "agent-auth-rs")
        for name in ["", "-agent-auth", "agent-auth-", "agent/auth", None]:
            with self.assertRaises(ValueError):
                canonical_pypi_name(name)

    def test_raw_and_labelled_tokens_exclude_recovery_material(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            path.touch(mode=0o600)
            for text in [
                "npm_exampleToken\n",
                "token=npm_exampleToken\nrecovery_code=LOCAL-RECOVERY-EXAMPLE\n",
                "# account settings\nNPM_TOKEN = npm_exampleToken\n\n",
            ]:
                path.write_text(text)
                self.assertEqual(read_npm_token(path), "npm_exampleToken")

    def test_ambiguous_or_malformed_credentials_fail_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            path.touch(mode=0o600)
            for text in [
                "npm_exampleToken\nnpm_secondToken\n",
                "token=npm_exampleToken\nNPM_TOKEN=npm_secondToken\n",
                "recovery_code=LOCAL-RECOVERY-EXAMPLE\n",
                "token=LOCAL-RECOVERY-EXAMPLE\n",
                "unknown=npm_exampleToken\n",
                "token=npm_exampleToken\nunknown=LOCAL-RECOVERY-EXAMPLE\n",
            ]:
                path.write_text(text)
                with self.assertRaises(ValueError) as failure:
                    read_npm_token(path)
                self.assertNotIn("LOCAL-RECOVERY-EXAMPLE", str(failure.exception))
                self.assertNotIn("npm_exampleToken", str(failure.exception))

    def test_public_permissions_symlinks_and_wrong_owner_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            path.write_text("npm_exampleToken")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_npm_token(path)
            path.chmod(0o600)
            link = Path(directory) / "linked"
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                read_npm_token(link)
            with patch("scripts.rs_sdk_release_utils.os.getuid", return_value=os.getuid() + 1):
                with self.assertRaises(ValueError):
                    read_npm_token(path)

    def test_size_encoding_nonregular_file_and_replacement_race_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials"
            path.touch(mode=0o600)
            for data in [b"npm_" + b"x" * 16_385, b"\xff"]:
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    read_npm_token(path)
            with self.assertRaises(ValueError):
                read_npm_token(Path(directory))
            path.write_text("npm_exampleToken")
            replacement = Path(directory) / "replacement"
            replacement.touch(mode=0o600)
            replacement.write_text("npm_secondToken")
            original_open = os.open

            def replace_before_open(name, flags):
                replacement.replace(path)
                return original_open(name, flags)

            with patch("scripts.rs_sdk_release_utils.os.open", side_effect=replace_before_open):
                with self.assertRaises(ValueError):
                    read_npm_token(path)


if __name__ == "__main__":
    unittest.main()
