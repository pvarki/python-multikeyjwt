"""Generate keypairs"""

from typing import Tuple, Union
from pathlib import Path
import logging


from libadvian.binpackers import ensure_utf8
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization


LOGGER = logging.getLogger(__name__)
KPTYPE = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_keypair(
    keyname: Path, password: Union[str, bytes, None], ktype: str = "RSA", ksize: int = 4096
) -> Tuple[Path, Path]:
    """Generate a keypair, give the path name of the .key -file and password, returns paths of
    .key and .pub"""
    if ktype in ("ECDSA", "EC"):
        LOGGER.info("Chose SECP256R1 for generic EC keypair")
        ktype = "SECP256R1"
    ckp: KPTYPE | None = None
    if ktype == "RSA":
        LOGGER.info("Generating {} keypair of size {}, this will take a moment".format(ktype, ksize))
        ckp = rsa.generate_private_key(public_exponent=65537, key_size=ksize)
    elif ktype in ("SECP256R1",):
        LOGGER.info("Generating {} keypair".format(ktype))
        ckp = ec.generate_private_key(getattr(ec, ktype)())
    else:
        raise NotImplementedError(f"Key type {ktype} not supported")
    keyenc: Union[serialization.NoEncryption, serialization.BestAvailableEncryption] = serialization.NoEncryption()
    if not password:
        LOGGER.warning("No password specified, keep the key extra-safe")
    else:
        keyenc = serialization.BestAvailableEncryption(ensure_utf8(password))

    with keyname.open("wb") as fpntr:
        fpntr.write(
            ckp.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=keyenc,
            )
        )
    LOGGER.info("Wrote {}".format(keyname))

    pubname = keyname.with_suffix(".pub")
    with pubname.open("wb") as fpntr:
        fpntr.write(
            ckp.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    LOGGER.info("Wrote {}".format(pubname))

    return keyname, pubname
