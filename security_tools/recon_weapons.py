"""
recon_weapons.py - grounding recon tools.

  - secret_scan  : regex-scan text or files for exposed secrets (keys/tokens/creds).
  - tech_detect  : fingerprint a target's stack from response headers + body.

Both are offline/deterministic (tech_detect fetches one URL). They turn raw output
into structured, actionable signal instead of leaving the model to eyeball it.
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# High-signal secret patterns. (name, regex, severity)
_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("AWS secret access key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})"),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    ("GitHub token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("Private key block", r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    ("Generic API key/token", r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*['\"]([^'\"\s]{6,60})['\"]"),
    ("Bearer token", r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{10,}"),
    ("Connection string w/ creds", r"(?i)(?:mongodb|postgres|postgresql|mysql|redis|amqp)://[^:\s]+:[^@\s]+@"),
]
_COMPILED = [(n, re.compile(p)) for n, p in _SECRET_PATTERNS]


class SecretScanTool(BaseTool):
    name = "secret_scan"
    description = (
        "Scan text or files for exposed secrets - API keys, AWS keys, private keys, JWTs, "
        "bearer tokens, DB connection strings, hardcoded passwords. Pass 'text' to scan a "
        "blob (a response body, a config you already read) or 'path' to scan a file or "
        "directory tree. Reports each hit with a redacted preview + where it was found."
    )
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Raw text to scan"},
            "path": {"type": "string", "description": "File or directory to scan"},
            "max_files": {"type": "integer", "description": "dir scan cap (default 300)", "default": 300},
        },
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["recon", "secrets", "credentials"]

    async def execute(self, text: str = "", path: str = "", max_files: int = 300,
                      **kwargs: Any) -> ToolResult:
        hits: list[str] = []
        if text:
            hits += self._scan_blob(text, "(inline text)")
        if path:
            if os.path.isfile(path):
                hits += self._scan_file(path)
            elif os.path.isdir(path):
                n = 0
                for root, _dirs, files in os.walk(path):
                    for fn in files:
                        if n >= max_files:
                            break
                        n += 1
                        hits += self._scan_file(os.path.join(root, fn))
            else:
                return ToolResult.fail(f"Path not found: {path}")
        if not text and not path:
            return ToolResult.fail("Provide 'text' or 'path' to scan.")
        if not hits:
            return ToolResult.ok("No secrets matched.")
        return ToolResult.ok(f"{len(hits)} potential secret(s):\n" + "\n".join(hits[:60]),
                             metadata={"count": len(hits)})

    def _scan_file(self, fp: str) -> list[str]:
        try:
            if os.path.getsize(fp) > 2_000_000:
                return []
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                return self._scan_blob(fh.read(), fp)
        except OSError:
            return []

    @staticmethod
    def _redact(s: str) -> str:
        s = s.strip()
        return s if len(s) <= 12 else s[:6] + "…" + s[-4:]

    def _scan_blob(self, blob: str, where: str) -> list[str]:
        out = []
        for name, rx in _COMPILED:
            for m in rx.finditer(blob):
                out.append(f"  [{name}] {self._redact(m.group(0))}  ({where})")
        return out


# Body/header signatures → technology. (regex, label)
_TECH_SIGS: list[tuple[str, str]] = [
    (r"(?i)werkzeug", "Werkzeug/Flask (Python)"),
    (r"(?i)django|csrftoken", "Django (Python)"),
    (r"(?i)express", "Express (Node.js)"),
    (r"(?i)x-powered-by:\s*php|\.php", "PHP"),
    (r"(?i)laravel_session|laravel", "Laravel (PHP)"),
    (r"(?i)wp-content|wordpress", "WordPress"),
    (r"(?i)x-aspnet-version|__viewstate", "ASP.NET"),
    (r"(?i)jsessionid|apache-coyote", "Java servlet (Tomcat)"),
    (r"(?i)ruby|rack|_rails_session", "Ruby on Rails"),
    (r"(?i)server:\s*nginx", "nginx"),
    (r"(?i)server:\s*apache", "Apache httpd"),
    (r"(?i)server:\s*amazons3|x-amz-", "AWS S3 / CloudFront"),
    (r"(?i)cf-ray|cloudflare", "Cloudflare"),
    (r"(?i)graphql", "GraphQL endpoint present"),
    (r"(?i)jquery|react|vue|angular", "JS framework (SPA) - read the JS"),
    (r"(?i)swagger|openapi", "Swagger/OpenAPI docs exposed"),
]


class TechDetectTool(BaseTool):
    name = "tech_detect"
    description = (
        "Fingerprint a target's technology stack from its HTTP response (headers + body): "
        "server, language/framework, WAF/CDN, and telltale endpoints (GraphQL, Swagger). "
        "Knowing the stack picks the right attack (e.g. Werkzeug→Jinja2 SSTI, PHP→LFI "
        "filters, ASP.NET→viewstate)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL (http/https)"},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    tags = ["recon", "fingerprint", "tech"]

    def __init__(self, session: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.session = session

    async def execute(self, url: str = "", **kwargs: Any) -> ToolResult:
        if not url.startswith(("http://", "https://")):
            return ToolResult.fail("url must start with http:// or https://")
        from browser.http_client import HttpClient
        cookies = getattr(self.session, "cookies", None)
        async with HttpClient(timeout=15.0, cookies=cookies) as client:
            resp = await client.get(url)
        hdr_txt = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        blob = hdr_txt + "\n" + (resp.text or "")[:8000]
        found: list[str] = []
        for rx, label in _TECH_SIGS:
            if re.search(rx, blob) and label not in found:
                found.append(label)
        server = next((v for k, v in (resp.headers or {}).items()
                       if k.lower() == "server"), "")
        powered = next((v for k, v in (resp.headers or {}).items()
                        if k.lower() == "x-powered-by"), "")
        lines = [f"Tech fingerprint of {url} (status {resp.status_code}):"]
        if server:
            lines.append(f"  Server: {server}")
        if powered:
            lines.append(f"  X-Powered-By: {powered}")
        lines.append("  Detected: " + (", ".join(found) if found else "(no strong signatures)"))
        return ToolResult.ok("\n".join(lines),
                             metadata={"detected": found, "server": server})
