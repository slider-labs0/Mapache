"""Live cloud instance metadata service (IMDS) - standard library only.

Models an AWS-style metadata endpoint with IMDSv1 ENABLED: credentials and user-data
are retrievable over plain HTTP with NO token/authentication. Combined with any SSRF
(or local access) this is instance-credential theft - a very common real-world cloud
finding. There is no CTF flag; the finding is the unauthenticated credential exposure.

Retrievable without a token:
  /latest/meta-data/iam/security-credentials/            -> role name
  /latest/meta-data/iam/security-credentials/s3-access-role -> temp STS credentials
  /latest/user-data                                      -> bootstrap script w/ a secret
The correct posture is IMDSv2 (a PUT-issued session token, required on every GET,
plus a low hop limit). This server deliberately does not require it.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = "s3-access-role"
CREDS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLECLOUDCREDS",
    "SecretAccessKey": "wCloudExampleSecret/StolenViaIMDSv1+abc123",
    "Token": "FQoGZXIvYXdzEXAMPLESESSIONTOKENstolen==",
    "Expiration": "2026-12-31T23:59:59Z",
}
USER_DATA = (
    "#!/bin/bash\n"
    "# bootstrap - provisions the app\n"
    "export DB_HOST=prod-db.internal\n"
    "export DB_PASSWORD='Sup3rS3cr3tProdDbPw!'   # hardcoded secret in user-data\n"
    "aws s3 sync s3://acme-prod-config /etc/app/\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        # IMDSv1: no token required (that is the weakness).
        self.send_header("Server", "EC2ws")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?", 1)[0]
        if p in ("/", "/latest", "/latest/", "/latest/meta-data",
                 "/latest/meta-data/"):
            return self._send(200, "ami-id\ninstance-id\niam/\nuser-data\n")
        if p.rstrip("/") == "/latest/meta-data/iam/security-credentials":
            return self._send(200, ROLE)
        if p == f"/latest/meta-data/iam/security-credentials/{ROLE}":
            return self._send(200, json.dumps(CREDS, indent=2), "application/json")
        if p == "/latest/user-data":
            return self._send(200, USER_DATA)
        if p == "/latest/meta-data/instance-id":
            return self._send(200, "i-0abcd1234efgh5678")
        return self._send(404, "not found")

    def do_PUT(self):
        # A hardened IMDSv2 client would PUT here for a token; we accept it but do NOT
        # require it on GET, so IMDSv1 access still works (the finding).
        self._send(200, "AQAEEXAMPLE-IMDSv2-TOKEN==")


if __name__ == "__main__":
    print("IMDS (IMDSv1 enabled, no token required) on 8080")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
