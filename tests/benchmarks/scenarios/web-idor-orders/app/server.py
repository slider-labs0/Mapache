"""Live vulnerable Orders API - standard library only (no pip, no build).

Reproduces a real IDOR / broken object-level authorization: an authenticated user
can read ANY order by id, including other users' orders, because get_order never
checks ownership. Two seeded users; alice can read bob's order (id 1002) and see a
sensitive note. There is no CTF flag - the "win" is diagnosing the authz flaw.

Seed:
  alice / password123   -> owns order 1001
  bob   / hunter2       -> owns order 1002  (note: "MERGER-ACME-CONFIDENTIAL")
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

USERS = {"alice": "password123", "bob": "hunter2"}
ORDERS = {
    1001: {"id": 1001, "user": "alice", "symbol": "AAPL", "qty": 10, "note": "personal"},
    1002: {"id": 1002, "user": "bob", "symbol": "TSLA", "qty": 99,
           "note": "MERGER-ACME-CONFIDENTIAL"},
}
# Trivial session tokens (token -> username). Handed out at /login.
SESSIONS = {"tok-alice": "alice", "tok-bob": "bob"}


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self):
        # Session via Authorization: Bearer <token>
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return SESSIONS.get(auth[7:].strip())
        return None

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._json(200, {
                "service": "Orders API",
                "endpoints": ["/login (POST user,password)",
                              "/api/orders (GET, your orders)",
                              "/api/orders/<id> (GET one order)"],
                "hint": "log in as alice, then read orders by id"})
        who = self._user()
        if u.path == "/api/orders":
            if not who:
                return self._json(401, {"error": "login required"})
            mine = [o for o in ORDERS.values() if o["user"] == who]
            return self._json(200, mine)
        if u.path.startswith("/api/orders/"):
            if not who:
                return self._json(401, {"error": "login required"})
            try:
                oid = int(u.path.rsplit("/", 1)[1])
            except ValueError:
                return self._json(400, {"error": "bad id"})
            order = ORDERS.get(oid)
            if not order:
                return self._json(404, {"error": "not found"})
            # *** VULNERABILITY: no check that order["user"] == who ***
            return self._json(200, order)
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode() if length else ""
            try:
                data = json.loads(raw) if raw.strip().startswith("{") else \
                    {k: v[0] for k, v in parse_qs(raw).items()}
            except Exception:
                data = {}
            user, pw = data.get("user", ""), data.get("password", "")
            if USERS.get(user) == pw:
                return self._json(200, {"token": f"tok-{user}"})
            return self._json(401, {"error": "bad credentials"})
        return self._json(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
