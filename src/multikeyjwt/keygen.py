"""Generate keypairs"""
from typing import Tuple, Union
from pathlib import Path
import logging


from libadvian.binpackers import ensure_utf8
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


LOGGER = logging.getLogger(__name__)


def generate_keypair(keyname: Path, password: Union[str, bytes, None]) -> Tuple[Path, Path]:
    """Generate a keypair, give the path name of the .key -file and password, returns paths of
    .key and .pub"""
    keypair = rsa.generate_private_key(
        public_exponent=65537,  # see https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
        key_size=4096,
    )
    keyenc: Union[serialization.NoEncryption, serialization.BestAvailableEncryption] = serialization.NoEncryption()
    if not password:
        LOGGER.warning("No password specified, keep the key extra-safe")
    else:
        keyenc = serialization.BestAvailableEncryption(ensure_utf8(password))

    with keyname.open("wb") as fpntr:
        fpntr.write(
            keypair.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=keyenc,
            )
        )
    LOGGER.info("Wrote {}".format(keyname))

    pubname = keyname.with_suffix(".pub")
    with pubname.open("wb") as fpntr:
        fpntr.write(
            keypair.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    LOGGER.info("Wrote {}".format(pubname))

    return keyname, pubname
