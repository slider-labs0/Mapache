"""cloud_enum.py - post-credential cloud account enumeration + misconfig/privesc triage.

Once credentials are in hand (e.g. stolen from IMDS via ssrf_probe/cloud_metadata, or a
leaked key), this drives the provider CLI to enumerate the account and PARSES the output
for the high-value findings: who am I, public storage, over-permissioned / privesc-prone
IAM, exposed secrets, and reachable compute. Command-building and parsing are pure and
testable; execute() runs the CLI through the shell and degrades gracefully when the CLI
isn't installed (it hands back the exact command to run on a box that has it).
"""

from __future__ import annotations

import re
import shutil
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# provider -> cli binary + install hint
_CLI = {"aws": ("aws", "pip install awscli"),
        "azure": ("az", "https://aka.ms/azcli"),
        "gcp": ("gcloud", "https://cloud.google.com/sdk")}

# action -> {provider: command}. Read-only enumeration only.
_COMMANDS: dict[str, dict[str, str]] = {
    "whoami": {
        "aws": "aws sts get-caller-identity",
        "azure": "az account show -o json",
        "gcp": "gcloud auth list --format=json && gcloud config list --format=json",
    },
    "storage": {
        "aws": "aws s3api list-buckets --output json",
        "azure": "az storage account list -o json",
        "gcp": "gsutil ls",
    },
    "iam": {
        # The authorization details dump is where privesc paths live.
        "aws": "aws iam get-account-authorization-details --output json",
        "azure": "az role assignment list --all -o json",
        "gcp": "gcloud projects get-iam-policy $(gcloud config get-value project) --format=json",
    },
    "compute": {
        "aws": "aws ec2 describe-instances --output json",
        "azure": "az vm list -d -o json",
        "gcp": "gcloud compute instances list --format=json",
    },
    "secrets": {
        "aws": "aws secretsmanager list-secrets --output json",
        "azure": "az keyvault list -o json",
        "gcp": "gcloud secrets list --format=json",
    },
}

# IAM permissions that enable privilege escalation (a subset of the well-known set).
_PRIVESC_PERMS = [
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
    "sts:AssumeRole", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction", "glue:CreateDevEndpoint", "cloudformation:CreateStack",
    "ec2:RunInstances", "ssm:SendCommand", "ssm:StartSession",
]


def build_cloud_command(action: str, provider: str = "aws") -> str:
    """The read-only enumeration command for (provider, action). Pure/testable."""
    provider = (provider or "aws").lower()
    action = (action or "whoami").lower()
    cmds = _COMMANDS.get(action, {})
    return cmds.get(provider, "")


def parse_cloud_output(action: str, output: str) -> dict:
    """Extract the high-value findings from an enumeration command's output."""
    action = (action or "").lower()
    out = output or ""
    findings: list[str] = []

    if action == "iam":
        # Admin / wildcard policy.
        if re.search(r'"Action"\s*:\s*"\*"', out) or re.search(r'"Action"\s*:\s*\[\s*"\*"', out):
            findings.append("A policy grants Action:'*' (full admin) - if attached to this "
                            "principal, you already own the account.")
        found = [p for p in _PRIVESC_PERMS if p in out]
        if found:
            findings.append("Privesc-prone permissions present: " + ", ".join(sorted(set(found)))
                            + " - build the matching escalation (e.g. PassRole+RunInstances, "
                            "CreatePolicyVersion, AttachUserPolicy -> AdministratorAccess).")
    if action == "storage":
        buckets = re.findall(r'"Name"\s*:\s*"([^"]+)"', out)
        if buckets:
            findings.append(f"{len(buckets)} bucket(s): {', '.join(buckets[:8])} - check each "
                            "for public ACL/policy (aws s3api get-bucket-acl/get-bucket-policy) "
                            "and list objects.")
    if action == "secrets":
        names = re.findall(r'"Name"\s*:\s*"([^"]+)"', out)
        if names:
            findings.append(f"{len(names)} secret(s) reachable: {', '.join(names[:8])} - "
                            "get-secret-value on each (creds/keys often here).")
    if action == "whoami":
        arn = re.search(r'"Arn"\s*:\s*"([^"]+)"', out)
        if arn:
            findings.append(f"Identity: {arn.group(1)}")
    if action == "compute":
        ips = re.findall(r'"PublicIpAddress"\s*:\s*"([^"]+)"', out)
        if ips:
            findings.append(f"{len(ips)} instance(s) with a public IP: {', '.join(ips[:8])} - "
                            "reachable attack surface; check SGs and SSM access.")
    return {"findings": findings}


class CloudEnumTool(BaseTool):
    """Enumerate a cloud account with credentials in hand and triage the loot: identity,
    public storage, privesc-prone IAM, exposed secrets, reachable compute. Runs the
    provider CLI (aws/az/gcloud) read-only and parses the result; hands back the command
    if the CLI is not installed here."""

    name = "cloud_enum"
    description = (
        "Enumerate a cloud account you have credentials for (AWS/Azure/GCP) and triage "
        "the findings. action: whoami | storage | iam | compute | secrets. It runs the "
        "provider CLI read-only and flags the wins - public buckets, admin/privesc IAM "
        "(iam:PassRole, CreatePolicyVersion, AttachUserPolicy, sts:AssumeRole...), "
        "reachable secrets, and public instances. Credentials come from the environment "
        "(e.g. keys stolen from IMDS via ssrf_probe/cloud_metadata). Read-only; respect scope."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": ["whoami", "storage", "iam", "compute", "secrets"],
                       "description": "What to enumerate.", "default": "whoami"},
            "provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
        },
        "required": ["action"],
    }
    permissions = {Permission.NETWORK, Permission.SHELL}
    timeout = 120
    tags = ["cloud", "iam", "enumeration"]

    def __init__(self, backend: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.backend = backend

    async def execute(self, action: str = "whoami", provider: str = "aws",
                      **kwargs: Any) -> ToolResult:
        provider = (provider or "aws").lower()
        if provider not in _CLI:
            return ToolResult.fail(f"cloud_enum: provider must be one of {', '.join(_CLI)}.")
        cmd = build_cloud_command(action, provider)
        if not cmd:
            return ToolResult.fail(
                f"cloud_enum: no '{action}' command for {provider} (actions: "
                f"{', '.join(_COMMANDS)}).")
        binary, hint = _CLI[provider]

        # Prefer the execution backend (a remote/pivot box) when present; else local.
        if self.backend is not None:
            try:
                res = await self.backend.run(cmd, timeout=self.timeout)
                output = getattr(res, "output", "") or str(res)
            except Exception as exc:
                return ToolResult.fail(f"cloud_enum: backend run failed - {exc}")
        elif shutil.which(binary) is None:
            return ToolResult.ok(
                f"[{binary} not installed here - {hint}]\nRun on a box with the CLI + these "
                f"credentials:\n  {cmd}", metadata={"command": cmd})
        else:
            import asyncio
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                raw, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                output = raw.decode("utf-8", "replace")
            except Exception as exc:
                return ToolResult.fail(f"cloud_enum: ran `{cmd}` but it failed - {exc}")

        parsed = parse_cloud_output(action, output)
        head = f"cloud_enum {provider}/{action}:\n  $ {cmd}\n"
        if parsed["findings"]:
            return ToolResult.ok(
                head + "\nFINDINGS:\n" + "\n".join(f"  - {f}" for f in parsed["findings"])
                + f"\n\n(raw output, truncated:)\n{output[:1500]}",
                metadata={"provider": provider, "action": action,
                          "findings": len(parsed["findings"])})
        return ToolResult.ok(
            head + f"\nNo high-value finding parsed. Raw output:\n{output[:2000]}",
            metadata={"provider": provider, "action": action, "findings": 0})
