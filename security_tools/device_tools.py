"""device_tools.py - static analysis for mobile apps and IoT firmware.

Two local, dependency-free static scanners that turn a file/tree into concrete findings:

- mobile_scan: an APK/IPA (or a decompiled tree) - risky manifest flags (debuggable,
  cleartext traffic, exported components, dangerous permissions) plus hardcoded secrets
  (API keys, private keys, cleartext endpoints, credentials) found across the package.
- firmware_scan: an extracted-firmware directory (or a raw blob) - hardcoded OS accounts
  (/etc/passwd, /etc/shadow), private keys / authorized_keys, credentials in config
  files, API tokens, and backdoor-shell hints.

Both are read-only, offline, and evidence-first: every finding is a concrete string /
flag located in the target, not a guess.
"""

from __future__ import annotations

import os
import re
import zipfile
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# Shared high-signal secret patterns (label, compiled regex).
_SECRET_RES: list[tuple[str, "re.Pattern"]] = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("AWS secret key", re.compile(rb"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?([A-Za-z0-9/+]{40})")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("Firebase URL", re.compile(rb"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(rb"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Stripe key", re.compile(rb"[sr]k_live_[0-9A-Za-z]{24,}")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    ("Private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Hardcoded credential", re.compile(rb"(?i)(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[=:]\s*['\"]([^'\"\s]{4,40})['\"]")),
    ("Cleartext endpoint", re.compile(rb"http://[a-zA-Z0-9.\-]+(?::\d+)?/[^\s'\"<>]{0,60}")),
]

_ANDROID_PERM_RE = re.compile(rb"android\.permission\.[A-Z_]+")
_DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_STATE",
}


def _scan_bytes(data: bytes, where: str, cap: int = 8) -> list[str]:
    hits: list[str] = []
    for label, rx in _SECRET_RES:
        for m in rx.finditer(data):
            frag = m.group(0)[:80].decode("latin-1", "ignore")
            hits.append(f"{label}: {frag}  [{where}]")
            if len([h for h in hits if h.startswith(label)]) >= cap:
                break
    return hits


class MobileScanTool(BaseTool):
    """Static-analyze an Android APK / iOS IPA (or a decompiled tree) for risky manifest
    configuration and hardcoded secrets - the fast mobile triage before dynamic work."""

    name = "mobile_scan"
    description = (
        "Static-analyze a mobile app: an Android .apk, iOS .ipa, or an already-decompiled "
        "directory. Reports risky Android manifest flags (android:debuggable, "
        "usesCleartextTraffic, allowBackup, exported components, dangerous permissions) and "
        "hardcoded secrets across the package (API keys, private keys, JWTs, cleartext "
        "endpoints, credentials). Offline/read-only. Give `path` to the file/tree."
    )
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Path to the .apk/.ipa or decompiled dir."}},
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 60
    tags = ["mobile", "android", "ios", "static-analysis"]

    def _manifest_flags(self, manifest: bytes) -> list[str]:
        flags: list[str] = []
        low = manifest.lower()
        if b"debuggable" in low and b"true" in low:
            flags.append("android:debuggable=true - the app is debuggable in production.")
        if b"usescleartexttraffic" in low and b"true" in low:
            flags.append("usesCleartextTraffic=true - allows unencrypted HTTP traffic.")
        if b"allowbackup" in low and b"true" in low:
            flags.append("allowBackup=true - app data can be extracted via adb backup.")
        if b"android:exported=\"true\"" in low or b"exported=true" in low:
            flags.append("exported components present - review activities/services/receivers "
                         "for unauthenticated invocation (drozer / adb am start).")
        perms = sorted({p.decode().split(".")[-1] for p in _ANDROID_PERM_RE.findall(manifest)})
        dangerous = [p for p in perms if p in _DANGEROUS_PERMS]
        if dangerous:
            flags.append("Dangerous permissions requested: " + ", ".join(dangerous))
        return flags

    async def execute(self, path: str, **kwargs: Any) -> ToolResult:
        path = (path or "").strip()
        if not path or not os.path.exists(path):
            return ToolResult.fail(f"mobile_scan: path not found: {path!r}")
        secrets: list[str] = []
        flags: list[str] = []
        scanned = 0
        try:
            if os.path.isfile(path) and zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as z:
                    for name in z.namelist():
                        if scanned > 400:
                            break
                        # Skip huge media; scan code/config/resources.
                        if name.endswith((".png", ".jpg", ".webp", ".ttf", ".mp4", ".ogg")):
                            continue
                        try:
                            data = z.read(name)
                        except Exception:
                            continue
                        scanned += 1
                        if name.endswith("AndroidManifest.xml") or name == "Info.plist":
                            flags += self._manifest_flags(data)
                        secrets += _scan_bytes(data, name, cap=4)
            else:  # a directory tree
                for root, _dirs, files in os.walk(path):
                    for fn in files:
                        if scanned > 800:
                            break
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, "rb") as fh:
                                data = fh.read(500_000)
                        except Exception:
                            continue
                        scanned += 1
                        if fn == "AndroidManifest.xml" or fn == "Info.plist":
                            flags += self._manifest_flags(data)
                        secrets += _scan_bytes(data, os.path.relpath(fp, path), cap=4)
        except Exception as exc:
            return ToolResult.fail(f"mobile_scan: failed - {exc}")

        secrets = list(dict.fromkeys(secrets))[:30]
        flags = list(dict.fromkeys(flags))
        lines = [f"mobile_scan - {path}  ({scanned} entries scanned)"]
        if flags:
            lines.append("\nMANIFEST / CONFIG RISKS:")
            lines += [f"  - {f}" for f in flags]
        if secrets:
            lines.append("\nHARDCODED SECRETS:")
            lines += [f"  - {s}" for s in secrets]
        if not flags and not secrets:
            lines.append("\nNo risky manifest flags or hardcoded secrets found in the static "
                         "scan. Next: decompile (jadx/apktool) and review logic, then dynamic "
                         "(frida/objection) for SSL pinning / runtime secrets.")
        else:
            lines.append("\nNext: confirm exported components (drozer), and test the app's API "
                         "backend for authz/IDOR with http_repeater.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"secrets": len(secrets), "flags": len(flags)})


class FirmwareScanTool(BaseTool):
    """Hunt an extracted-firmware tree (or a raw blob) for the classic embedded-device
    wins: hardcoded OS accounts, private keys, credentials in configs, API tokens, and
    backdoor-shell hints."""

    name = "firmware_scan"
    description = (
        "Scan extracted firmware (a directory tree from binwalk, or a raw blob) for the "
        "classic embedded wins: hardcoded accounts (/etc/passwd, /etc/shadow hashes), "
        "private keys / authorized_keys, credentials in *.conf/*.ini/*.sh, API tokens, "
        "hardcoded IPs/URLs, and backdoor shells (telnetd/dropbear). Offline/read-only. "
        "Give `path` to the extracted root; for a raw .bin, extract with binwalk first "
        "(the tool notes this)."
    )
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Extracted firmware dir (or a raw firmware file)."}},
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 60
    tags = ["iot", "firmware", "static-analysis"]

    async def execute(self, path: str, **kwargs: Any) -> ToolResult:
        path = (path or "").strip()
        if not path or not os.path.exists(path):
            return ToolResult.fail(f"firmware_scan: path not found: {path!r}")
        accounts: list[str] = []
        keys: list[str] = []
        secrets: list[str] = []
        notes: list[str] = []

        if os.path.isfile(path):
            notes.append("This is a single file. If it is a raw firmware image, extract it "
                         "first: `binwalk -eM " + path + "` then scan the extracted root. "
                         "Scanning its strings anyway:")
            try:
                with open(path, "rb") as fh:
                    secrets += _scan_bytes(fh.read(2_000_000), os.path.basename(path), cap=6)
            except Exception as exc:
                return ToolResult.fail(f"firmware_scan: {exc}")
        else:
            for root, _dirs, files in os.walk(path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    rel = os.path.relpath(fp, path)
                    low = fn.lower()
                    try:
                        with open(fp, "rb") as fh:
                            data = fh.read(400_000)
                    except Exception:
                        continue
                    if fn == "passwd" or rel.endswith("etc/passwd"):
                        for line in data.decode("latin-1", "ignore").splitlines():
                            parts = line.split(":")
                            if len(parts) >= 7 and parts[6].strip().rstrip("/").endswith(("sh",)):
                                accounts.append(f"login shell account: {parts[0]} ({parts[6]}) [{rel}]")
                    if fn == "shadow" or rel.endswith("etc/shadow"):
                        for line in data.decode("latin-1", "ignore").splitlines():
                            p = line.split(":")
                            if len(p) >= 2 and p[1] and p[1] not in ("*", "!", "!!", "x"):
                                accounts.append(f"CRACKABLE hash: {p[0]}:{p[1][:24]}… [{rel}] "
                                                "(feed to john/hashcat)")
                    if low in ("authorized_keys",) or low.endswith(".pem") or low.endswith("_key"):
                        keys.append(f"key material: {rel}")
                    if b"-----BEGIN" in data and b"PRIVATE KEY" in data:
                        keys.append(f"embedded PRIVATE KEY: {rel}")
                    if any(b in low for b in ("telnetd", "dropbear")) or b"/bin/telnetd" in data:
                        notes.append(f"backdoor-shell binary/reference: {rel}")
                    if low.endswith((".conf", ".ini", ".cfg", ".sh", ".env", ".xml", ".json")):
                        secrets += _scan_bytes(data, rel, cap=3)

        accounts = list(dict.fromkeys(accounts))[:20]
        keys = list(dict.fromkeys(keys))[:20]
        secrets = list(dict.fromkeys(secrets))[:30]
        notes = list(dict.fromkeys(notes))
        total = len(accounts) + len(keys) + len(secrets)
        lines = [f"firmware_scan - {path}"]
        if notes:
            lines += ["", *[f"  ! {n}" for n in notes]]
        if accounts:
            lines.append("\nACCOUNTS / HASHES:")
            lines += [f"  - {a}" for a in accounts]
        if keys:
            lines.append("\nKEY MATERIAL:")
            lines += [f"  - {k}" for k in keys]
        if secrets:
            lines.append("\nSECRETS IN CONFIG:")
            lines += [f"  - {s}" for s in secrets]
        if total == 0:
            lines.append("\nNo hardcoded accounts/keys/secrets found. Next: check the web "
                         "UI / services for default creds and known CVEs (searchsploit on "
                         "the device model + firmware version).")
        return ToolResult.ok("\n".join(lines),
                             metadata={"accounts": len(accounts), "keys": len(keys),
                                       "secrets": len(secrets)})
