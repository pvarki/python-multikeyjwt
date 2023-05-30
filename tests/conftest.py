"""pytest automagics"""
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner
from libadvian.logging import init_logging

from multikeyjwt import Issuer, Verifier
from multikeyjwt.config import Secret


init_logging(logging.DEBUG)
LOGGER = logging.getLogger(__name__)
DATA_PATH = Path(__file__).parent / Path("data")


@pytest.fixture(scope="session")
def issuer_rr() -> Issuer:
    """issuer using rr-key"""
    return Issuer(
        privkeypath=DATA_PATH / Path("rr_jwtRS256.key"),
        keypasswd=Secret("Rimmed_Radiated_Pliable_Perjury"),  # pragma: allowlist secret
    )


@pytest.fixture(scope="session")
def issuer_cl() -> Issuer:
    """issuer using cl-key"""
    return Issuer(
        privkeypath=DATA_PATH / Path("cl_jwtRS256.key"),
        keypasswd=Secret("Cache_Latitude_Displease_Hardcopy"),  # pragma: allowlist secret
    )


@pytest.fixture(scope="session")
def issuer_pc() -> Issuer:
    """issuer using pc-key"""
    return Issuer(
        privkeypath=DATA_PATH / Path("pc_jwtRS256.key"),
        keypasswd=Secret("Pacific_Catsup_Police_Slicing"),  # pragma: allowlist secret
    )


@pytest.fixture(scope="session")
def verifier() -> Verifier:
    """issuer using all keys in data"""
    return Verifier(pubkeypath=DATA_PATH)


@pytest.fixture(scope="module")
def runner() -> CliRunner:
    """CLI runner"""
    return CliRunner()


@pytest.fixture(scope="function")
def token(tmp_path: Path) -> Path:
    """Token fixture"""
    iss = Issuer(
        privkeypath=DATA_PATH / Path("rr_jwtRS256.key"),
        keypasswd=Secret("Rimmed_Radiated_Pliable_Perjury"),  # pragma: allowlist secret
    )

    tokenfile = tmp_path / "token.txt"
    tokenfile.write_text(iss.issue({"foo": "bar"}))

    return tokenfile
