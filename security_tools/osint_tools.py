"""Passive OSINT tools - deeper multi-source search, phone-number intel, and
social-account cross-referencing (e.g. surfacing the LinkedIn behind an Instagram
handle).

STRICTLY PASSIVE. These tools read public / third-party sources only - search
engines and public profile pages - and never touch a target's own systems. They
back the OSINT Operator (core/operators.py) and the osint_recon playbook.

All HTTP goes through browser.http_client.HttpClient so it honours the active
egress (direct / proxy / Tor). Every tool degrades gracefully when a source is
rate-limited or a page shape changes: it returns whatever it could gather plus
the search dorks the operator can pivot on by hand.
"""

from __future__ import annotations

import html as _html
import re
import urllib.parse
from typing import Any

from browser.http_client import HttpClient
from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

_DDG_HTML = "https://html.duckduckgo.com/html/"

# Search-engine result hosts we never want to surface as a "finding" - they are the
# engine itself, ads, or its redirector, not the subject.
_NOISE_HOSTS = (
    "duckduckgo.com", "google.com", "bing.com", "yahoo.com", "youtube.com/redirect",
    "r.jina.ai",
)

# Platform -> hostname fragment, used both to build dorks and to bucket results.
_PLATFORMS = {
    "linkedin": "linkedin.com/in",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "facebook": "facebook.com",
    "tiktok": "tiktok.com",
    "github": "github.com",
    "reddit": "reddit.com/user",
    "youtube": "youtube.com",
    "telegram": "t.me",
}

_BREACH_PASTE = (
    "pastebin.com", "ghostbin", "throwbin", "gist.github.com", "breachforums",
    "haveibeenpwned.com", "dehashed.com", "leakcheck", "raidforums", "doxbin",
)


def _clean(text: str) -> str:
    return _html.unescape(re.sub(r"<[^>]+>", "", text or "")).strip()


def _host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


async def _ddg(client: HttpClient, query: str, limit: int = 8) -> list[dict]:
    """One DuckDuckGo HTML search. Returns [{url,title,snippet}]. Best-effort:
    an empty list on failure (rate-limit / shape change), never raises."""
    resp = await client.post(
        _DDG_HTML,
        data={"q": query, "b": "", "kl": ""},
        extra_headers={"Content-Type": "application/x-www-form-urlencoded",
                       "User-Agent": _UA},
    )
    if not resp.success:
        return []
    out: list[dict] = []
    for url, title, snippet in re.findall(
        r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?'
        r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
        resp.text, re.DOTALL | re.IGNORECASE,
    ):
        url = url.replace("//duckduckgo.com/l/?uddg=", "")
        url = urllib.parse.unquote(url.split("&uddg=")[-1].split("&rut=")[0])
        url = urllib.parse.unquote(url.split("&")[0])
        title, snippet = _clean(title), _clean(snippet)
        if url.startswith("http") and title:
            out.append({"url": url, "title": title, "snippet": snippet})
        if len(out) >= limit:
            break
    return out


class OsintSearchTool(BaseTool):
    """Deeper OSINT search: fans one subject out into targeted search-engine dorks
    (social profiles, leaks/pastes, documents, code) and returns the correlated,
    de-duplicated results bucketed by category - far more than a single web_search."""

    name = "osint_search"
    description = (
        "Deep passive OSINT search on a person, username, email, phone, or org. "
        "Runs several targeted search-engine dorks in one call (social profiles, "
        "breach/paste mentions, exposed documents, public code) and returns the "
        "correlated, de-duplicated results grouped by category. Passive - reads "
        "search engines only. Use `kind` to bias the dorks (person/username/email/"
        "phone/org/domain)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "subject": {"type": "string",
                        "description": "Name, username, email, phone, org, or domain to research."},
            "kind": {"type": "string",
                     "enum": ["auto", "person", "username", "email", "phone", "org", "domain"],
                     "description": "What the subject is (biases the dorks). Default auto.",
                     "default": "auto"},
            "max_results": {"type": "integer",
                            "description": "Max results per category (default 6, max 12).",
                            "default": 6},
        },
        "required": ["subject"],
    }
    permissions = {Permission.NETWORK}
    timeout = 45
    tags = ["osint", "recon", "search", "passive"]

    def __init__(self, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    @staticmethod
    def _guess_kind(subject: str) -> str:
        s = subject.strip()
        if "@" in s and "." in s.split("@")[-1]:
            return "email"
        if re.fullmatch(r"[+()\-.\s0-9]{7,}", s):
            return "phone"
        if re.fullmatch(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", s):
            return "domain"
        if re.fullmatch(r"[a-zA-Z0-9._]+", s) and " " not in s:
            return "username"
        return "person"

    def _dorks(self, subject: str, kind: str) -> list[tuple[str, str]]:
        """(category, query) pairs. Categories: social, leaks, docs, code, general."""
        q = subject.strip()
        quoted = f'"{q}"' if " " in q or kind in ("person", "org") else q
        social_sites = ("linkedin.com", "instagram.com", "twitter.com OR x.com",
                        "facebook.com", "tiktok.com", "github.com")
        dorks: list[tuple[str, str]] = []
        for site in social_sites:
            dorks.append(("social", f"{quoted} site:{site}"))
        dorks.append(("leaks", f"{quoted} (site:pastebin.com OR site:gist.github.com OR "
                                "breach OR leak OR password OR dump)"))
        dorks.append(("docs", f"{quoted} (filetype:pdf OR filetype:xlsx OR filetype:docx)"))
        dorks.append(("code", f"{quoted} (site:github.com OR site:gitlab.com OR "
                               "site:pastebin.com)"))
        if kind == "email":
            user = q.split("@")[0]
            dorks.append(("general", f'"{user}"'))
            dorks.append(("leaks", f'"{q}" (breach OR haveibeenpwned OR dehashed)'))
        elif kind == "domain":
            dorks.append(("general", f"site:{q}"))
            dorks.append(("docs", f"site:{q} (filetype:pdf OR filetype:xlsx OR ext:log)"))
        else:
            dorks.append(("general", quoted))
        return dorks

    async def execute(self, subject: str, kind: str = "auto",
                      max_results: int = 6, **kwargs: Any) -> ToolResult:
        subject = (subject or "").strip()
        if not subject:
            return ToolResult.fail("osint_search: 'subject' is required")
        if kind in (None, "", "auto"):
            kind = self._guess_kind(subject)
        cap = min(max(1, max_results), 12)

        buckets: dict[str, list[dict]] = {}
        seen: set[str] = set()
        errors = 0
        try:
            async with HttpClient(timeout=15.0, proxy=self._proxy(),
                                  headers={"User-Agent": _UA}) as client:
                for category, query in self._dorks(subject, kind):
                    rows = await _ddg(client, query, limit=cap + 4)
                    if not rows:
                        errors += 1
                    for r in rows:
                        h = _host(r["url"])
                        if not h or any(n in r["url"] for n in _NOISE_HOSTS):
                            continue
                        key = r["url"].rstrip("/").lower()
                        if key in seen:
                            continue
                        seen.add(key)
                        # bucket by the platform it actually landed on when we can
                        cat = category
                        if any(p in h for p in ("linkedin", "instagram", "twitter",
                                                "x.com", "facebook", "tiktok", "github")):
                            cat = "social"
                        elif any(b in r["url"].lower() for b in _BREACH_PASTE):
                            cat = "leaks"
                        buckets.setdefault(cat, []).append(r)
        except Exception as exc:  # network stack / proxy failure
            if not buckets:
                return ToolResult.fail(f"osint_search: search failed - {exc}")

        if not any(buckets.values()):
            return ToolResult.ok(
                f"osint_search: no public results for {subject!r} (kind={kind}). "
                "Sources may be rate-limiting; try a narrower subject or a direct "
                "profile lookup with social_lookup.",
                metadata={"subject": subject, "kind": kind, "result_count": 0})

        order = ["social", "leaks", "docs", "code", "general"]
        lines = [f"OSINT search - {subject!r} (kind={kind})\n"]
        total = 0
        for cat in order:
            rows = buckets.get(cat) or []
            if not rows:
                continue
            lines.append(f"[{cat.upper()}]")
            for r in rows[:cap]:
                total += 1
                lines.append(f"  - {r['title']}")
                lines.append(f"    {r['url']}")
                if r.get("snippet"):
                    lines.append(f"    {r['snippet'][:200]}")
            lines.append("")
        if errors:
            lines.append(f"(note: {errors} dork(s) returned nothing - possible rate-limit)")
        return ToolResult.ok("\n".join(lines).rstrip(),
                             metadata={"subject": subject, "kind": kind,
                                       "result_count": total})


# --- Phone-number intel ----------------------------------------------------- #

# Minimal country-code table for the no-dependency fallback (phonenumbers lib is
# used when installed). Covers the common calling codes; unknown codes still get
# formatting + dorks.
_CC = {
    "1": "US/Canada (NANP)", "44": "United Kingdom", "33": "France", "49": "Germany",
    "34": "Spain", "39": "Italy", "31": "Netherlands", "351": "Portugal", "353": "Ireland",
    "61": "Australia", "64": "New Zealand", "81": "Japan", "82": "South Korea",
    "86": "China", "852": "Hong Kong", "886": "Taiwan", "91": "India", "92": "Pakistan",
    "971": "UAE", "966": "Saudi Arabia", "972": "Israel", "90": "Turkey", "7": "Russia/Kazakhstan",
    "55": "Brazil", "52": "Mexico", "54": "Argentina", "57": "Colombia", "56": "Chile",
    "27": "South Africa", "234": "Nigeria", "254": "Kenya", "20": "Egypt", "212": "Morocco",
    "63": "Philippines", "62": "Indonesia", "60": "Malaysia", "65": "Singapore",
    "66": "Thailand", "84": "Vietnam", "48": "Poland", "46": "Sweden", "47": "Norway",
    "45": "Denmark", "358": "Finland", "41": "Switzerland", "43": "Austria", "32": "Belgium",
    "30": "Greece", "420": "Czechia", "36": "Hungary", "40": "Romania", "380": "Ukraine",
}


class PhoneLookupTool(BaseTool):
    """Passive phone-number intel: validate + format a number (country, region,
    line type when the phonenumbers library is present), then generate the OSINT
    search dorks to trace it across search engines, social platforms, and
    caller-ID / reverse-lookup sites. No calls or texts are placed - passive only."""

    name = "phone_lookup"
    description = (
        "Passive phone-number OSINT. Parses and validates a phone number - country, "
        "region/carrier hint, national + E.164 format, line type - and returns "
        "ready-to-run OSINT search dorks (search engines, social platforms, "
        "caller-ID/reverse-lookup sites) to trace who it belongs to. Never dials or "
        "texts the number. Give the number with a country code when possible "
        "(e.g. +1 415 555 0100), or pass `region` (ISO like US/GB) to help parsing."
    )
    parameters = {
        "type": "object",
        "properties": {
            "number": {"type": "string",
                       "description": "The phone number, ideally in +CC format (e.g. +14155550100)."},
            "region": {"type": "string",
                       "description": "ISO-3166 region hint (US, GB, DE...) when no + country code.",
                       "default": ""},
        },
        "required": ["number"],
    }
    permissions = {Permission.NETWORK}
    timeout = 20
    tags = ["osint", "phone", "recon", "passive"]

    def __init__(self, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress

    @staticmethod
    def _fallback_parse(raw: str) -> dict:
        digits = re.sub(r"[^\d+]", "", raw)
        e164 = digits if digits.startswith("+") else None
        country = None
        national = re.sub(r"\D", "", raw)
        if e164:
            body = e164[1:]
            for length in (3, 2, 1):  # longest calling code first
                cc = body[:length]
                if cc in _CC:
                    country = _CC[cc]
                    national = body[length:]
                    break
        return {"e164": e164, "country": country, "national": national,
                "valid": bool(e164 and national and len(national) >= 6)}

    def _variants(self, raw: str, parsed: dict) -> list[str]:
        # Deterministic priority order (E.164 and human-readable groupings first),
        # de-duplicated while preserving order. NOT a set - set iteration order is
        # randomized by PYTHONHASHSEED, which would drop useful formats from the
        # capped dork list on some runs.
        digits = re.sub(r"\D", "", raw)
        nat = re.sub(r"\D", "", parsed.get("national") or "") or digits
        ordered: list[str] = []
        if parsed.get("e164"):
            ordered.append(parsed["e164"])
        if len(nat) == 10:  # US-style grouping, most useful for reverse lookups
            ordered += [f"({nat[:3]}) {nat[3:6]}-{nat[6:]}",
                        f"{nat[:3]}-{nat[3:6]}-{nat[6:]}",
                        f"{nat[:3]}.{nat[3:6]}.{nat[6:]}"]
        ordered += [raw.strip(), nat, digits]
        seen: set[str] = set()
        return [v for v in ordered if v and not (v in seen or seen.add(v))]

    async def execute(self, number: str, region: str = "", **kwargs: Any) -> ToolResult:
        number = (number or "").strip()
        if not number:
            return ToolResult.fail("phone_lookup: 'number' is required")

        info: dict[str, Any] = {}
        lib = "fallback"
        try:
            import phonenumbers  # type: ignore
            from phonenumbers import carrier, geocoder, number_type, PhoneNumberType
            reg = (region or "").upper() or None
            pn = phonenumbers.parse(number, reg)
            valid = phonenumbers.is_valid_number(pn)
            ntype = number_type(pn)
            type_name = {
                PhoneNumberType.MOBILE: "mobile",
                PhoneNumberType.FIXED_LINE: "fixed line",
                PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
                PhoneNumberType.VOIP: "VoIP",
                PhoneNumberType.TOLL_FREE: "toll-free",
                PhoneNumberType.PREMIUM_RATE: "premium-rate",
            }.get(ntype, "unknown")
            info = {
                "valid": valid,
                "e164": phonenumbers.format_number(
                    pn, phonenumbers.PhoneNumberFormat.E164),
                "national": phonenumbers.format_number(
                    pn, phonenumbers.PhoneNumberFormat.NATIONAL),
                "international": phonenumbers.format_number(
                    pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "country_code": pn.country_code,
                "country": geocoder.description_for_number(pn, "en") or None,
                "carrier": carrier.name_for_number(pn, "en") or None,
                "line_type": type_name,
            }
            lib = "phonenumbers"
        except ImportError:
            fb = self._fallback_parse(number)
            info = {"valid": fb["valid"], "e164": fb["e164"],
                    "national": fb["national"], "country": fb["country"],
                    "line_type": "unknown", "carrier": None}
        except Exception as exc:
            fb = self._fallback_parse(number)
            info = {"valid": fb["valid"], "e164": fb["e164"],
                    "national": fb["national"], "country": fb["country"],
                    "line_type": "unknown", "carrier": None,
                    "parse_note": f"phonenumbers could not parse ({exc}); used fallback"}

        variants = self._variants(number, info)
        # Reverse-lookup / caller-ID dorks the operator can open (all passive).
        v0 = info.get("e164") or variants[0]
        dorks = [
            f'"{v}"' for v in variants[:4]
        ]
        lookup_sites = [
            f"https://www.truecaller.com/search/us/{re.sub(chr(92)+'D','',v0)}",
            f"https://www.google.com/search?q={urllib.parse.quote(v0)}",
            "https://www.whocalld.com/", "https://sync.me/search/",
        ]

        lines = [f"phone_lookup - {number}  (parser: {lib})", ""]
        lines.append(f"  valid:      {info.get('valid')}")
        if info.get("e164"):
            lines.append(f"  E.164:      {info['e164']}")
        if info.get("international"):
            lines.append(f"  intl:       {info['international']}")
        if info.get("national"):
            lines.append(f"  national:   {info['national']}")
        if info.get("country"):
            lines.append(f"  country:    {info['country']}")
        if info.get("carrier"):
            lines.append(f"  carrier:    {info['carrier']}")
        lines.append(f"  line type:  {info.get('line_type', 'unknown')}")
        if info.get("parse_note"):
            lines.append(f"  note:       {info['parse_note']}")
        if lib == "fallback":
            lines.append("  (install `phonenumbers` for carrier/line-type/region data)")
        lines.append("")
        lines.append("Search dorks (open with web_search / osint_search):")
        for d in dorks:
            lines.append(f"  - {d}")
            lines.append(f"  - {d} (site:linkedin.com OR site:facebook.com OR site:instagram.com)")
        lines.append("")
        lines.append("Reverse-lookup / caller-ID sites (open with web_fetch):")
        for s in lookup_sites:
            lines.append(f"  - {s}")

        return ToolResult.ok("\n".join(lines),
                             metadata={"number": number, "parser": lib,
                                       "valid": bool(info.get("valid"))})


# --- Social-account cross-referencing --------------------------------------- #

class SocialLookupTool(BaseTool):
    """Cross-reference a social handle to the person's other profiles - built for the
    classic 'find the LinkedIn behind an Instagram account' pivot. Reads the public
    profile page for identity signals (full name, bio, external link) and then
    searches for matching profiles on LinkedIn and the other platforms. Passive:
    only public profile pages + search engines; no login, no following, no DMs."""

    name = "social_lookup"
    description = (
        "Cross-reference a social-media handle to the same person's other accounts - "
        "e.g. surface the LinkedIn profile behind an Instagram username. Reads the "
        "PUBLIC profile page for identity signals (full name, bio, linked website) "
        "then searches LinkedIn (and Twitter/X, GitHub, Facebook, TikTok) for matching "
        "profiles. Passive: public pages + search only, no login/follow/DM. Set "
        "`platform` (default instagram) and `find` (default linkedin, or 'all')."
    )
    parameters = {
        "type": "object",
        "properties": {
            "username": {"type": "string",
                         "description": "The handle to start from (without the @)."},
            "platform": {"type": "string",
                         "enum": list(_PLATFORMS.keys()),
                         "description": "Which platform the username is on. Default instagram.",
                         "default": "instagram"},
            "find": {"type": "string",
                     "description": "Target platform to cross-reference to: 'linkedin' "
                                    "(default), any platform name, or 'all'.",
                     "default": "linkedin"},
        },
        "required": ["username"],
    }
    permissions = {Permission.NETWORK}
    timeout = 40
    tags = ["osint", "social", "recon", "passive"]

    def __init__(self, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    async def _profile_identity(self, client: HttpClient, platform: str,
                                username: str) -> dict:
        """Pull identity signals from a public profile page. Best-effort - returns
        {full_name, bio, external, title}. Instagram/Twitter expose og: meta tags
        even to logged-out fetches; other platforms fall back to <title>/meta."""
        base = {
            "instagram": f"https://www.instagram.com/{username}/",
            "twitter": f"https://twitter.com/{username}",
            "x": f"https://x.com/{username}",
            "tiktok": f"https://www.tiktok.com/@{username}",
            "github": f"https://github.com/{username}",
            "facebook": f"https://www.facebook.com/{username}",
            "telegram": f"https://t.me/{username}",
        }.get(platform, f"https://www.{_PLATFORMS.get(platform, platform)}/{username}")

        ident = {"url": base, "full_name": None, "bio": None, "external": None,
                 "title": None}
        resp = await client.get(base, extra_headers={"User-Agent": _UA})
        if not resp.success or not resp.text:
            return ident
        t = resp.text

        def meta(prop: str) -> str | None:
            m = re.search(
                rf'<meta[^>]+(?:property|name)=["\']{re.escape(prop)}["\'][^>]+'
                r'content=["\'](.*?)["\']', t, re.IGNORECASE | re.DOTALL)
            return _clean(m.group(1)) if m else None

        og_title = meta("og:title") or meta("twitter:title")
        og_desc = meta("og:description") or meta("twitter:description") or meta("description")
        ident["title"] = og_title
        if og_title:
            # "Full Name (@handle) - Instagram" style
            ident["full_name"] = re.split(r"[(•|·]|\s[-–]\s", og_title)[0].strip() or None
        ident["bio"] = og_desc
        # external link in bio (Instagram/linktree etc.)
        ext = re.search(r'https?://(?:l\.instagram\.com/\?u=)?([^\s"\'<>]+linktr\.ee[^\s"\'<>]*)', t)
        if not ext:
            ext = re.search(r'"external_url":"(https?:[^"]+)"', t)
        if ext:
            ident["external"] = urllib.parse.unquote(ext.group(1)).replace("\\u0026", "&")
        return ident

    async def execute(self, username: str, platform: str = "instagram",
                      find: str = "linkedin", **kwargs: Any) -> ToolResult:
        username = (username or "").lstrip("@").strip()
        if not username:
            return ToolResult.fail("social_lookup: 'username' is required")
        platform = (platform or "instagram").lower()
        find = (find or "linkedin").lower()

        try:
            async with HttpClient(timeout=15.0, proxy=self._proxy(),
                                  headers={"User-Agent": _UA}) as client:
                ident = await self._profile_identity(client, platform, username)

                # Build the identity query: prefer real name, else the handle.
                name = ident.get("full_name")
                targets = list(_PLATFORMS.keys()) if find == "all" else [find]
                found: dict[str, list[dict]] = {}
                # Search terms to correlate on: full name (strongest), handle, and
                # any distinctive bio words.
                base_terms = [t for t in (name, username) if t]
                for tgt in targets:
                    site = _PLATFORMS.get(tgt, tgt)
                    rows: list[dict] = []
                    for term in base_terms:
                        q = f'"{term}" site:{site}' if " " in term else f"{term} site:{site}"
                        rows += await _ddg(client, q, limit=6)
                        if rows:
                            break
                    # dedupe + keep only results actually on the target platform
                    seen, keep = set(), []
                    for r in rows:
                        if site.split("/")[0] not in _host(r["url"]):
                            continue
                        k = r["url"].rstrip("/").lower()
                        if k in seen:
                            continue
                        seen.add(k)
                        keep.append(r)
                    if keep:
                        found[tgt] = keep[:5]
        except Exception as exc:
            return ToolResult.fail(f"social_lookup: failed - {exc}")

        lines = [f"social_lookup - @{username} on {platform}", ""]
        lines.append(f"  profile:  {ident.get('url')}")
        if ident.get("full_name"):
            lines.append(f"  name:     {ident['full_name']}")
        if ident.get("bio"):
            lines.append(f"  bio:      {ident['bio'][:220]}")
        if ident.get("external"):
            lines.append(f"  link:     {ident['external']}")
        if not any(ident.get(k) for k in ("full_name", "bio", "external")):
            lines.append("  (profile page gave no public identity signals - login-walled; "
                         "cross-referencing on the handle alone)")
        lines.append("")

        if not found:
            lines.append(f"No matching {find} profile found from public search. "
                         "Try osint_search on the real name, or widen with find='all'.")
            return ToolResult.ok("\n".join(lines),
                                 metadata={"username": username, "platform": platform,
                                           "matches": 0})

        total = 0
        for tgt, rows in found.items():
            lines.append(f"[{tgt.upper()} candidates]")
            for r in rows:
                total += 1
                lines.append(f"  - {r['title']}")
                lines.append(f"    {r['url']}")
                if r.get("snippet"):
                    lines.append(f"    {r['snippet'][:160]}")
            lines.append("")
        lines.append("NOTE: search-derived candidates - confirm the match by name/photo/"
                     "bio before treating any profile as the same person.")
        return ToolResult.ok("\n".join(lines).rstrip(),
                             metadata={"username": username, "platform": platform,
                                       "target": find, "matches": total})
