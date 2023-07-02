"""Test CLI scripts"""
import asyncio
import json
import uuid
from pathlib import Path

import pytest
from libadvian.binpackers import ensure_str

from multikeyjwt import __version__
from multikeyjwt.console import cli_group as cli


@pytest.mark.asyncio
async def test_version_cli():  # type: ignore
    """Test the CLI parsing for default version dumping works"""
    cmd = "multikeyjwt --version"
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out = await asyncio.wait_for(process.communicate(), 10)
    # Demand clean exit
    assert process.returncode == 0
    # Check output
    assert ensure_str(out[0]).strip().endswith(__version__)


def test_verify_cli(runner, token):  # type: ignore
    """Test verify-command"""
    result = runner.invoke(cli, ["verify", token.read_text(), "-k", "tests/data/rr_jwtRS256.pub"])

    assert "foo" in json.loads(result.output)
    assert result.exit_code == 0


def test_sign_cli(runner):  # type: ignore
    """Test sign-command"""
    result = runner.invoke(cli, ["sign", "tests/data/rr_jwtRS256.key", "-p", "Rimmed_Radiated_Pliable_Perjury"])

    assert result.exit_code == 0


def test_genkey_cli(runner, nice_tmpdir):  # type: ignore
    """Test genkey-command"""
    keypath = Path(nice_tmpdir) / Path("gentest.key")
    password = str(uuid.uuid4())
    result = runner.invoke(cli, ["genkey", str(keypath), "-p", password])
    assert result.exit_code == 0

    result2 = runner.invoke(cli, ["sign", str(keypath), "-p", password])
    assert result2.exit_code == 0
