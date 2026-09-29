"""CLI smoke tests for RFC 6901 JSON Pointer.

Category 8: CLI smoke (10 tests).
"""

import subprocess
import sys
import json
import pytest


def _run_cli(args, input_json=None):
    """Run the CLI and return (stdout, stderr, exit_code)."""
    cmd = [sys.executable, "-m", "rfc6901jsonpointer"] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_json,
    )
    return result.stdout, result.stderr, result.returncode


class TestCLI:
    """Category 8: CLI smoke tests."""

    def test_cli_simple_key(self):
        stdout, stderr, rc = _run_cli(["/foo", '{"foo": 42}'])
        assert rc == 0, f"Expected rc=0, got {rc}. stderr={stderr}"
        assert stdout.strip() == "42"

    def test_cli_nested_key(self):
        stdout, stderr, rc = _run_cli(["/a/b", '{"a": {"b": "nested"}}'])
        assert rc == 0
        assert stdout.strip() == '"nested"'

    def test_cli_array_index(self):
        stdout, stderr, rc = _run_cli(["/0", '["first", "second", "third"]'])
        assert rc == 0
        assert stdout.strip() == '"first"'

    def test_cli_missing_key(self):
        stdout, stderr, rc = _run_cli(["/nonexistent", '{"foo": 1}'])
        assert rc != 0
        assert "JSONPointerError" in stderr
        assert "key not found" in stderr

    def test_cli_out_of_bounds(self):
        stdout, stderr, rc = _run_cli(["/99", '["a", "b"]'])
        assert rc != 0
        assert "JSONPointerError" in stderr
        assert "out of bounds" in stderr

    def test_cli_invalid_pointer(self):
        stdout, stderr, rc = _run_cli(["foo", '{"foo": 1}'])
        assert rc != 0
        assert "JSONPointerError" in stderr

    def test_cli_invalid_json(self):
        stdout, stderr, rc = _run_cli(["/foo", "not valid json"])
        assert rc != 0
        assert "JSON" in stderr or "json" in stderr.lower()

    def test_cli_empty_pointer(self):
        stdout, stderr, rc = _run_cli(["", '{"foo": 1}'])
        assert rc == 0
        # Empty pointer returns whole document
        result = json.loads(stdout.strip())
        assert result == {"foo": 1}

    def test_cli_help_or_usage(self):
        # No args should exit with code 1 and show usage
        stdout, stderr, rc = _run_cli([])
        assert rc == 1
        assert "Usage" in stderr or "usage" in stderr

    def test_cli_evaluate_none_document(self):
        # This tests pointer evaluation failure (not parse failure)
        stdout, stderr, rc = _run_cli(["/foo", "null"])
        assert rc != 0
        assert "JSONPointerError" in stderr

    def test_cli_special_chars_in_key(self):
        stdout, stderr, rc = _run_cli(["/a~1b", '{"a/b": "slash_key"}'])
        assert rc == 0
        assert stdout.strip() == '"slash_key"'

    def test_cli_tilde_unescape(self):
        stdout, stderr, rc = _run_cli(["/a~0b", '{"a~b": "tilde_key"}'])
        assert rc == 0
        assert stdout.strip() == '"tilde_key"'
