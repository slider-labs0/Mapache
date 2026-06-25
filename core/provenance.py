"""
provenance.py — local signing for synthesized skills (feature N)

Feature A's trust model verifies a *hub* tool's code against a sha256 in its
manifest; provenance adds the next layer — a signature proving WHO authored a
skill and that its code is untampered. It is where feature N's "signed packages"
requirement lives, ahead of the community hub (I) that will distribute them.

v1 is deliberately dependency-free: an HMAC-SHA256 over the code's sha256, keyed
by a per-machine secret in `~/.mapache/skill_key` (created on first use, 0600).
That gives Mapache a stable signer identity and tamper-evidence for the skills it
synthesizes locally. Cross-machine trust (verifying *another* operator's signing
key) is the hub's job — an asymmetric (ed25519) upgrade can drop in here behind
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
