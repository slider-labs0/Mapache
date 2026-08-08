"""
http_history.py - a Burp-lite request/response store for the web tools.

Every HTTP request the agent sends is recorded here as an `HTTPExchange` with a
short id (`r1`, `r2`, …). That gives the agent three capabilities it otherwise
lacks - the ones a human uses Burp Repeater for:

  * **replay** an earlier request verbatim,
  * **tamper** - replay it with one field changed (an id, a header, a param),
  * **diff** - compare two responses.

This is what turns IDOR / broken-authz from guesswork into a mechanical check:
replay the authenticated request with `id=124` instead of `id=123` and diff -
a DIFFERENT body means you just read another user's object (a confirmed IDOR);
an IDENTICAL body means the parameter is ignored (a dead vector).

The store is shared (like `WebSession`) across the web tools and, because
delegated sub-agents reuse the lead's tool dispatcher + instances, across every
operator in a swarm - so a request captured by recon is replayable by exploit.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

# Bodies can be large; cap what we retain per exchange so history stays bounded.
_MAX_BODY = 20000


@dataclass
class HTTPExchange:
    """One recorded request + its response, enough to replay and diff."""
    id: str
    method: str
    url: str
    req_headers: dict = field(default_factory=dict)
    req_params: Optional[dict] = None
    req_json: Any = None
    req_data: Optional[dict] = None
    req_body: Optional[str] = None
    status: int = 0
    resp_headers: dict = field(default_factory=dict)
    resp_body: str = ""
    elapsed_ms: float = 0.0
    ts: float = field(default_factory=time.time)
    tag: str = ""

    def summary(self) -> str:
        n = len(self.resp_body or "")
        t = f" [{self.tag}]" if self.tag else ""
        return f"{self.id}: {self.method} {self.url} -> {self.status} ({n}B){t}"


class HTTPHistory:
    """Bounded, id-addressable log of HTTP exchanges."""

    def __init__(self, maxlen: int = 256) -> None:
        self._items: deque = deque(maxlen=maxlen)
        self._by_id: dict[str, HTTPExchange] = {}
        self._counter = 0

    def record(self, *, method: str, url: str, status: int,
               req_headers: Optional[dict] = None, req_params: Optional[dict] = None,
               req_json: Any = None, req_data: Optional[dict] = None,
               req_body: Optional[str] = None, resp_headers: Optional[dict] = None,
               resp_body: str = "", elapsed_ms: float = 0.0, tag: str = "") -> HTTPExchange:
        self._counter += 1
        ex = HTTPExchange(
            id=f"r{self._counter}", method=(method or "GET").upper(), url=url,
            req_headers=dict(req_headers or {}), req_params=req_params,
            req_json=req_json, req_data=req_data, req_body=req_body,
            status=status, resp_headers=dict(resp_headers or {}),
            resp_body=(resp_body or "")[:_MAX_BODY], elapsed_ms=elapsed_ms, tag=tag)
        # Evict the id of whatever the bounded deque drops.
        if len(self._items) == self._items.maxlen and self._items:
            self._by_id.pop(self._items[0].id, None)
        self._items.append(ex)
        self._by_id[ex.id] = ex
        return ex

    def get(self, ex_id: str) -> Optional[HTTPExchange]:
        return self._by_id.get((ex_id or "").strip())

    def recent(self, n: int = 20) -> list[HTTPExchange]:
        return list(self._items)[-n:]

    def search(self, needle: str) -> list[HTTPExchange]:
        q = (needle or "").lower()
        if not q:
            return []
        return [e for e in self._items
                if q in e.url.lower() or q in (e.resp_body or "").lower()]

    def __len__(self) -> int:
        return len(self._items)


def diff_bodies(a: str, b: str, max_lines: int = 40) -> tuple[bool, str]:
    """Unified diff of two response bodies. Returns (changed, rendered_diff)."""
    import difflib
    a_lines = (a or "").splitlines()
    b_lines = (b or "").splitlines()
    if a_lines == b_lines:
        return False, "(response bodies are IDENTICAL)"
    ud = list(difflib.unified_diff(a_lines, b_lines, lineterm="",
                                   fromfile="original", tofile="replay"))
    body = ud[2:] if len(ud) > 2 else ud  # drop the ---/+++ header lines
    shown = body[:max_lines]
    out = "\n".join(shown)
    if len(body) > max_lines:
        out += f"\n[... {len(body) - max_lines} more diff lines]"
    return True, out
