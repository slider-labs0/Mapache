"""
flag_verifier.py - candidate-flag verification (tail of the agent-loop plan)

The anti-fabrication guard already rejects a braced FLAG{…}/CTF{…} token that never
appeared in tool output. This adds the missing dimension: FORMAT. A verifier that knows
the engagement's expected flag shape can (a) recognise a real flag that isn't a generic
FLAG{…} (custom CTF/HTB/pico formats, a hex/UUID key), and (b) catch a token that is
grounded in output but does NOT match the expected format - a plausible-but-wrong
"success". A candidate is VERIFIED only when it is both grounded (seen in tool output)
and well-formed (matches the expected pattern, when one is set).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Generic flag shapes when no engagement-specific format is configured.
_BRACED_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[^}\r\n]{1,200}\}")


@dataclass
class FlagVerdict:
    candidate: str
    grounded: bool       # appeared verbatim in captured tool output
    well_formed: bool    # matches the expected format (or a generic flag shape)
    verified: bool       # grounded AND well_formed
    reason: str


class FlagVerifier:
    """Extract candidate flags from text and verify them against an optional expected
    format plus a corpus of captured tool output."""

    def __init__(self, expected_pattern: Optional[str] = None) -> None:
        self.expected: Optional[re.Pattern] = None
        if expected_pattern:
            try:
                self.expected = re.compile(expected_pattern)
            except re.error:
                self.expected = None  # a bad pattern must not break verification

    def candidates(self, text: str) -> list[str]:
        """Flag-like tokens in `text`: expected-format matches first, then generic
        braced tokens, de-duplicated in order."""
        if not text:
            return []
        out: list[str] = []
        if self.expected is not None:
            out += self.expected.findall(text)
        out += _BRACED_RE.findall(text)
        # findall may yield tuples if the pattern has groups - normalise to str.
        flat = [m if isinstance(m, str) else (m[0] if m else "") for m in out]
        return list(dict.fromkeys(t for t in flat if t))

    def _well_formed(self, candidate: str) -> bool:
        if self.expected is not None:
            return bool(self.expected.fullmatch(candidate) or self.expected.search(candidate))
        return bool(_BRACED_RE.fullmatch(candidate))

    def verify(self, candidate: str, corpus: str) -> FlagVerdict:
        grounded = bool(candidate) and candidate in (corpus or "")
        well_formed = self._well_formed(candidate)
        if grounded and well_formed:
            reason = "verified - grounded in tool output and matches the expected format"
        elif not grounded:
            reason = "fabricated - never appeared in this session's tool output"
        else:
            reason = "format mismatch - appeared in output but not the expected flag format"
        return FlagVerdict(candidate=candidate, grounded=grounded,
                           well_formed=well_formed,
                           verified=grounded and well_formed, reason=reason)

    def verify_all(self, text: str, corpus: str) -> list[FlagVerdict]:
        return [self.verify(c, corpus) for c in self.candidates(text)]
