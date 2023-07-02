"""CLI entrypoints for multikeyjwt"""
from typing import Any, Sequence
import logging
import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import click
from jwt import InvalidSignatureError
from libadvian.logging import init_logging

from multikeyjwt import __version__, Issuer, Verifier
from multikeyjwt.config import Secret
from multikeyjwt.keygen import generate_keypair


LOGGER = logging.getLogger(__name__)


def get_from_stdin(ctx: click.Context, param: Any, value: Any) -> Any:  # pylint: disable=unused-argument
    """Get value from stdin if value not given"""
    if not value and not click.get_text_stream("stdin").isatty():
        return click.get_text_stream("stdin").read().strip()

    return value


@click.group()
@click.version_option(version=__version__)
@click.pass_context
@click.option("-l", "--loglevel", help="Python log level, 10=DEBUG, 20=INFO, 30=WARNING, 40=CRITICAL", default=30)
@click.option("-v", "--verbose", count=True, help="Shorthand for info/debug loglevel (-v/-vv)")
def cli_group(ctx: click.Context, loglevel: int, verbose: int) -> None:
    """Verify JWTs with multiple public keys, FastAPI middleware for auth"""
    if verbose == 1:
        loglevel = 20
    if verbose >= 2:
        loglevel = 10

    LOGGER.setLevel(loglevel)
    ctx.ensure_object(dict)


@cli_group.command(name="verify")
@click.argument("token", callback=get_from_stdin, required=False)
@click.option("-k", "--keypath", help="Public key path", type=click.Path(exists=True))
def verify_cmd(token: str, keypath: Path) -> None:
    """
    Verify the given token with the given key.

    The token can be piped from stdin: cat token.txt | multikeyjwt verify -k key.pub \n
    or provided directly: multikeyjwt verify TOKENHERE -k key.pub
    """

    try:
        if not token:
            return click.echo("No token given!")

        verifier = Verifier(pubkeypath=Path(keypath))
        return click.echo(json.dumps(verifier.decode(token), indent=4))

    except InvalidSignatureError:
        return click.echo("Invalid signature!", err=True)


@cli_group.command(name="sign")
@click.argument("keypath", callback=get_from_stdin, required=False)
@click.option("-p", "--passphrase", help="Passhphrase to use", default=None)
@click.option("-c", "--claim", help="Claim to issue JWT with", type=(str, str), multiple=True)
def sign_cmd(keypath: str, passphrase: str, claim: Sequence[Any]) -> None:
    """
    Sign the given claims

    The key can be piped from stdin: cat mykey.key | multikeyjwt sign -p
      mypassphrase -c key value -c secondkey secondvalue \n
    or provided directly (as a path): multikeyjwt sign path/to/key.key -p
    mypassphrase -c key value -c secondkey secondvalue
    """

    if not keypath:
        return click.echo("No key given!")

    try:
        # Try to read keypath as a file or directory
        if Path(keypath).is_file() or Path(keypath).is_dir():
            try:
                issuer = Issuer(privkeypath=Path(keypath), keypasswd=Secret(passphrase))
                return click.echo(issuer.issue(dict(claim)))

            except TypeError:
                return click.echo("No passphrase given!")

    except IOError:
        pass

    # If keypath is not a file or directory, use it as one
    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(keypath.encode())
        tmpfile.seek(0)

        try:
            issuer = Issuer(privkeypath=Path(tmpfile.name), keypasswd=Secret(passphrase))
            return click.echo(issuer.issue(dict(claim)))

        except Exception as exc:  # pylint: disable=broad-except
            return click.echo(f"{exc}")


@cli_group.command(name="genkey")
@click.argument("keypath", required=True)
@click.option(
    "-p", "--passphrase", help="Passhphrase to use", prompt=True, hide_input=True, confirmation_prompt=True, default=""
)
def genkey_cmd(keypath: str, passphrase: str) -> None:
    """
    Generate a new keypair, give the path you wish the .key -file have
    """
    genkey, genpub = generate_keypair(Path(keypath), passphrase)
    click.echo(genkey)
    click.echo(genpub)


def multikeyjwt_cli() -> None:
    """CLI entrypoint"""
    init_logging(logging.WARNING)
    cli_group()  # pylint: disable=no-value-for-parameter
