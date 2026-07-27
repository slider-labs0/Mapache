"""hub — community skill hub (feature I): browse + install downloadable skills."""

from .manifest import (SkillManifest, payload_digest, verify_manifest,
                       make_generated_tool_manifest, make_mcp_server_manifest,
                       make_external_tool_manifest, VALID_TYPES)
from .registry import LocalRegistry, UrlRegistry, make_registry
from .client import HubClient
from .publish import (manifest_from_github, parse_repo_manifest, add_to_index,
                      install_to_config, integration_spec, parse_github,
                      normalize_tool_name, PublishError, REPO_MANIFEST_NAME)

__all__ = [
    "SkillManifest", "payload_digest", "verify_manifest",
    "make_generated_tool_manifest", "make_mcp_server_manifest",
    "make_external_tool_manifest", "VALID_TYPES",
    "LocalRegistry", "UrlRegistry", "make_registry", "HubClient",
    "manifest_from_github", "parse_repo_manifest", "add_to_index",
    "install_to_config", "integration_spec", "parse_github",
    "normalize_tool_name", "PublishError", "REPO_MANIFEST_NAME",
]
