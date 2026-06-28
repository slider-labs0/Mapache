"""hub — community skill hub (feature I): browse + install downloadable skills."""

from .manifest import (SkillManifest, payload_digest, verify_manifest,
                       make_generated_tool_manifest, make_mcp_server_manifest,
                       VALID_TYPES)
from .registry import LocalRegistry, UrlRegistry, make_registry
from .client import HubClient

__all__ = [
    "SkillManifest", "payload_digest", "verify_manifest",
    "make_generated_tool_manifest", "make_mcp_server_manifest", "VALID_TYPES",
    "LocalRegistry", "UrlRegistry", "make_registry", "HubClient",
]
