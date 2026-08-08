"""
provenance.py - local signing for synthesized skills (feature N)

Feature A's trust model verifies a *hub* tool's code against a sha256 in its
manifest; provenance adds the next layer - a signature proving WHO authored a
skill and that its code is untampered. It is where feature N's "signed packages"
requirement lives, ahead of the community hub (I) that will distribute them.

v1 is deliberately dependency-free: an HMAC-SHA256 over the code's sha256, keyed
by a per-machine secret in `~/.mapache/skill_key` (created on first use, 0600).
That gives Mapache a stable signer identity and tamper-evidence for the skills it
synthesizes locally. Cross-machine trust (verifying *another* operator's signing
key) is the hub's job - an asymmetric (ed25519) upgrade can drop in here behind
the same sign()/verify() surface when I lands.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Optional

SIGN_ALGO = "hmac-sha256-v1"


def _key_path(environ: Optional[dict[str, str]] = None) -> Path:
    environ = environ if environ is not None else dict(os.environ)
    home = environ.get("USERPROFILE") or environ.get("HOME") or str(Path.home())
    return Path(home) / ".mapache" / "skill_key"


def local_key(path: Optional[Path] = None) -> bytes:
    """Return the per-machine signing key, creating it (0600) on first use."""
    kp = Path(path) if path is not None else _key_path()
    if kp.is_file():
        return bytes.fromhex(kp.read_text(encoding="utf-8").strip())
    kp.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    kp.write_text(key.hex(), encoding="utf-8")
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return key


def signer_id(key: bytes) -> str:
    """A short, non-secret fingerprint of the signing key (identifies the signer)."""
    return "mapache-" + hashlib.sha256(key).hexdigest()[:12]


def sign(message: str, key: Optional[bytes] = None) -> str:
    key = key if key is not None else local_key()
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(message: str, signature: str, key: Optional[bytes] = None) -> bool:
    if not signature:
        return False
    key = key if key is not None else local_key()
    expected = sign(message, key)
    return hmac.compare_digest(expected, signature)


# --------------------------------------------------------------------------- #
# Cross-machine signatures - ed25519 (feature N upgrade, optional dependency)
# --------------------------------------------------------------------------- #
#
# HMAC above is per-machine: it proves a skill is untampered and identifies the
# signer to itself, but verifying *another* operator's signature needs the shared
# secret. ed25519 closes that gap (the hub's real goal): a publisher signs with a
# private key, anyone verifies with the public key - no shared secret. It needs
# the `cryptography` package; when absent these degrade safely (verify → False),
# and `verify_signed` keeps dispatching the always-available HMAC path.

SIGN_ALGO_ED25519 = "ed25519-v1"


def ed25519_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
        return True
    except ImportError:
        return False


def generate_keypair() -> Optional[tuple[str, str]]:
    """(private_pem, public_pem) hex-free PEM strings, or None if unavailable."""
    if not ed25519_available():
        return None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    return priv_pem, pub_pem


def sign_ed25519(message: str, private_pem: str) -> str:
    """Hex signature over the message with an ed25519 private key (PEM)."""
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    return priv.sign(message.encode("utf-8")).hex()


def verify_ed25519(message: str, signature_hex: str, public_pem: str) -> bool:
    """Verify an ed25519 signature with the publisher's public key. False on any
    error (bad sig, malformed key, library absent) - never raises."""
    if not signature_hex or not public_pem:
        return False
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        try:
            pub.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
            return True
        except InvalidSignature:
            return False
    except Exception:
        return False


def verify_signed(
    message: str,
    signature: str,
    *,
    algo: str = SIGN_ALGO,
    key: Optional[bytes] = None,
    public_pem: Optional[str] = None,
) -> bool:
    """Algorithm-aware verify: HMAC (per-machine) or ed25519 (cross-machine).
    Unknown/unavailable algo → False."""
    if algo == SIGN_ALGO:
        return verify(message, signature, key)
    if algo == SIGN_ALGO_ED25519:
        return verify_ed25519(message, signature, public_pem or "")
    return False
