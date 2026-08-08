"""
integration_catalog.py - known third-party services for just-in-time setup.

When the operator says "search this in Shodan" or "run this hash through
VirusTotal" and that integration isn't configured yet, the CLI recognises the
service, offers a one-question setup (paste the API key), writes the tool spec to
config (key kept as a ${ENV} ref), and makes it available on the spot.

Each recipe carries: the trigger words that name it, the env var its key lives in,
where to sign up, and the ready-made integration spec(s) (see tools/external_tools).
Adding a service here is all it takes to make it self-serve.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class IntegrationRecipe:
    key: str                       # canonical id, e.g. "shodan"
    display: str                   # "Shodan"
    env_var: str                   # "SHODAN_API_KEY"
    signup_url: str                # where to obtain a key
    blurb: str                     # one-line description
    triggers: tuple[str, ...]      # substrings in user input that name it
    specs: tuple[dict, ...]        # the integration spec(s) to register

    def spec_names(self) -> set:
        return {s["name"] for s in self.specs}


CATALOG: tuple[IntegrationRecipe, ...] = (
    IntegrationRecipe(
        key="shodan", display="Shodan", env_var="SHODAN_API_KEY",
        signup_url="https://account.shodan.io/",
        blurb="Passive host recon - open ports, services, banners, and known CVEs.",
        triggers=("shodan",),
        specs=(
            {"name": "shodan_host", "kind": "http", "method": "GET",
             "url": "https://api.shodan.io/shodan/host/{ip}?key=${SHODAN_API_KEY}",
             "description": "Shodan: open ports, services, banners, and known CVEs "
                            "for an IP (passive - no packets to the target).",
             "params": {"ip": {"type": "string", "description": "target IPv4",
                                "required": True}},
             "permission": "network"},
            {"name": "shodan_search", "kind": "http", "method": "GET",
             "url": "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}"
                    "&query={query}",
             "description": "Shodan search (e.g. 'apache country:US port:8080'). "
                            "Uses query credits.",
             "params": {"query": {"type": "string", "description": "Shodan query",
                                  "required": True}},
             "permission": "network"},
        ),
    ),
    IntegrationRecipe(
        key="virustotal", display="VirusTotal", env_var="VT_API_KEY",
        signup_url="https://www.virustotal.com/gui/my-apikey",
        blurb="Reputation for file hashes, IPs, and domains from 70+ AV/threat feeds.",
        triggers=("virustotal", "virus total", " vt "),
        specs=(
            {"name": "vt_file", "kind": "http", "method": "GET",
             "url": "https://www.virustotal.com/api/v3/files/{hash}",
             "headers": {"x-apikey": "${VT_API_KEY}"},
             "description": "VirusTotal report for a file hash (md5/sha1/sha256).",
             "params": {"hash": {"type": "string", "description": "file hash",
                                 "required": True}},
             "permission": "network"},
            {"name": "vt_ip", "kind": "http", "method": "GET",
             "url": "https://www.virustotal.com/api/v3/ip_addresses/{ip}",
             "headers": {"x-apikey": "${VT_API_KEY}"},
             "description": "VirusTotal reputation for an IP address.",
             "params": {"ip": {"type": "string", "description": "IP address",
                               "required": True}},
             "permission": "network"},
        ),
    ),
    IntegrationRecipe(
        key="greynoise", display="GreyNoise", env_var="GREYNOISE_API_KEY",
        signup_url="https://viz.greynoise.io/account/",
        blurb="Is an IP background-noise/scanner or targeted? Context on internet scanners.",
        triggers=("greynoise", "grey noise"),
        specs=(
            {"name": "greynoise_ip", "kind": "http", "method": "GET",
             "url": "https://api.greynoise.io/v3/community/{ip}",
             "headers": {"key": "${GREYNOISE_API_KEY}"},
             "description": "GreyNoise community context for an IP (noise/riot/classification).",
             "params": {"ip": {"type": "string", "description": "IP address",
                               "required": True}},
             "permission": "network"},
        ),
    ),
    IntegrationRecipe(
        key="abuseipdb", display="AbuseIPDB", env_var="ABUSEIPDB_API_KEY",
        signup_url="https://www.abuseipdb.com/account/api",
        blurb="Abuse/blocklist reputation and report history for an IP.",
        triggers=("abuseipdb", "abuse ipdb", "abuse ip db"),
        specs=(
            {"name": "abuseipdb_check", "kind": "http", "method": "GET",
             "url": "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
             "headers": {"Key": "${ABUSEIPDB_API_KEY}", "Accept": "application/json"},
             "description": "AbuseIPDB reputation/confidence score and reports for an IP.",
             "params": {"ip": {"type": "string", "description": "IP address",
                               "required": True}},
             "permission": "network"},
        ),
    ),
)

_BY_KEY = {r.key: r for r in CATALOG}


def get_recipe(key: str) -> Optional[IntegrationRecipe]:
    return _BY_KEY.get((key or "").lower())


def detect_missing_integration(
    user_input: str, configured_names: set, environ: Optional[dict] = None,
) -> Optional[IntegrationRecipe]:
    """The first catalog service named in the input that isn't fully READY, or None.

    'Ready' = its tool(s) are registered AND its API-key env var is set. So we also
    prompt when the spec exists but the key is missing (a call would just 401) -
    offering to add only the key in that case. An already-ready service never
    re-prompts."""
    environ = environ if environ is not None else os.environ
    names = set(configured_names)
    text = f" {(user_input or '').lower()} "
    for recipe in CATALOG:
        if not any(t in text for t in recipe.triggers):
            continue
        specs_present = recipe.spec_names() <= names
        key_set = bool(environ.get(recipe.env_var))
        if specs_present and key_set:
            continue  # fully ready - nothing to do
        return recipe
    return None


def is_configured(recipe: "IntegrationRecipe", configured_names: set) -> bool:
    """Whether the recipe's tool(s) are already registered (spec present)."""
    return recipe.spec_names() <= set(configured_names)
