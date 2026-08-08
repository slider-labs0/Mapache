"""
moltbook_tool.py - Mapache Moltbook integration

Gives Mapache a social presence on Moltbook - the social network for AI agents.
Handles registration, authentication, posting, commenting, voting, and feed reading.

API base: https://www.moltbook.com/api/v1
Docs:     https://www.moltbook.com/skill.md

Registration flow:
    1. moltbook_register  - creates account, returns api_key + claim_url
    2. Human opens claim_url, verifies email, posts claim tweet on X
    3. moltbook_status    - confirms account is claimed and active
    4. moltbook_post      - Mapache starts posting autonomously

Verification:
    Moltbook uses obfuscated math challenges to verify posts are from real AI agents.
    e.g. "A] lO^bSt-Er S[wImS aT/ tW]eNn-Tyy mE^tE[rS" → "a lobster swims at twenty meters"
    Mapache solves these automatically before content goes live.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

API_BASE = "https://www.moltbook.com/api/v1"
CREDENTIALS_FILE = Path.home() / ".config" / "mapache" / "moltbook.json"


# ------------------------------------------------------------------ #
# Credentials management
# ------------------------------------------------------------------ #

def load_credentials() -> dict:
    if CREDENTIALS_FILE.exists():
        try:
            return json.loads(CREDENTIALS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_credentials(data: dict) -> None:
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.write_text(json.dumps(data, indent=2))


def get_api_key() -> Optional[str]:
    creds = load_credentials()
    return creds.get("api_key") or os.environ.get("MOLTBOOK_API_KEY")


# ------------------------------------------------------------------ #
# HTTP helpers
# ------------------------------------------------------------------ #

async def _request(
    method: str,
    path: str,
    api_key: Optional[str] = None,
    json_data: Optional[dict] = None,
    params: Optional[dict] = None,
) -> dict:
    if not HAS_HTTPX:
        return {"success": False, "error": "httpx not installed: pip install httpx"}

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(
            method,
            f"{API_BASE}{path}",
            headers=headers,
            json=json_data,
            params=params,
        )

    try:
        return response.json()
    except Exception:
        return {"success": False, "error": f"HTTP {response.status_code}: {response.text[:200]}"}


# ------------------------------------------------------------------ #
# Verification challenge solver
# ------------------------------------------------------------------ #

def solve_verification_challenge(challenge_text: str) -> Optional[str]:
    """
    Solve Moltbook's obfuscated math challenges.

    Format: scrambled caps + symbols hiding a math word problem
    Example: "A] lO^bSt-Er S[wImS aT/ tW]eNn-Tyy mE^tE[rS aNd] SlO/wS bY^ fI[vE"
    Decoded: "a lobster swims at twenty meters and slows by five"
    Math: 20 - 5 = 15.00

    Strategy: strip noise → lowercase → find numbers → find operation → compute
    """
    # Strip non-alphabetic noise (keep spaces)
    clean = re.sub(r"[^a-zA-Z\s]", "", challenge_text).lower()
    clean = re.sub(r"\s+", " ", clean).strip()

    # Word-to-number mapping
    word_nums = {
        "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
        "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
        "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
        "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
        "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
        "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
        "eighty": 80, "ninety": 90, "hundred": 100,
    }

    # Compound numbers like "twenty five" = 25
    words = clean.split()
    numbers = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in word_nums:
            val = word_nums[w]
            # Check for compound: "twenty five" → 25
            if i + 1 < len(words) and words[i + 1] in word_nums:
                next_val = word_nums[words[i + 1]]
                if val >= 20 and next_val < 10:
                    val += next_val
                    i += 1
            numbers.append(val)
        i += 1

    if len(numbers) < 2:
        return None

    a, b = numbers[0], numbers[1]

    # Detect operation from keywords
    op_keywords = {
        "add": "+", "adds": "+", "plus": "+", "and": "+", "total": "+",
        "subtract": "-", "minus": "-", "less": "-", "slows": "-",
        "removes": "-", "loses": "-", "drops": "-", "decreases": "-",
        "multiply": "*", "times": "*", "multiplied": "*",
        "divide": "/", "divided": "/", "splits": "/",
    }

    operation = "+"  # default
    for word in words:
        if word in op_keywords:
            operation = op_keywords[word]
            break

    if operation == "+":
        result = a + b
    elif operation == "-":
        result = a - b
    elif operation == "*":
        result = a * b
    elif operation == "/" and b != 0:
        result = a / b
    else:
        result = a + b

    return f"{result:.2f}"


# ------------------------------------------------------------------ #
# Tools
# ------------------------------------------------------------------ #

class MoltbookRegisterTool(BaseTool):
    name = "moltbook_register"
    description = (
        "Register Mapache as an AI agent on Moltbook - the social network for AI agents. "
        "Creates an account, saves credentials locally, and returns a claim_url for the human "
        "owner to verify via X (Twitter). Must be called once before using other Moltbook tools."
    )
    parameters = {
        "type": "object",
        "properties": {
            "agent_name": {
                "type": "string",
                "description": "Name for the Moltbook account (e.g. 'MapacheAgent')",
            },
            "description": {
                "type": "string",
                "description": "Short bio describing what Mapache does",
                "default": "A locally-run AI agent built for security research and automation.",
            },
        },
        "required": ["agent_name"],
    }
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(self, agent_name: str, description: str = "", **kwargs: Any) -> ToolResult:
        # Check if already registered
        existing = load_credentials()
        if existing.get("api_key"):
            return ToolResult.ok(
                f"Already registered as '{existing.get('agent_name', 'unknown')}'.\n"
                f"API key exists. Use moltbook_status to check claim status.\n"
                f"Credentials: {CREDENTIALS_FILE}"
            )

        result = await _request("POST", "/agents/register", json_data={
            "name": agent_name,
            "description": description or "A locally-run AI agent for security research and automation.",
        })

        if not result.get("success", True) and result.get("error"):
            return ToolResult.fail(f"Registration failed: {result.get('error')}")

        agent = result.get("agent", {})
        api_key = agent.get("api_key")
        claim_url = agent.get("claim_url")
        verification_code = agent.get("verification_code")

        if not api_key:
            return ToolResult.fail(f"No API key in response: {json.dumps(result)[:300]}")

        # Save credentials
        creds = {
            "api_key": api_key,
            "agent_name": agent_name,
            "claim_url": claim_url,
            "verification_code": verification_code,
        }
        save_credentials(creds)

        output = [
            f"Mapache registered on Moltbook as '{agent_name}'!",
            f"",
            f"API key saved to: {CREDENTIALS_FILE}",
            f"",
            f"NEXT STEP - Human action required:",
            f"1. Open this URL: {claim_url}",
            f"2. Verify your email address",
            f"3. Post this tweet on X: 'Claiming my AI agent {agent_name} on @moltbook #{verification_code}'",
            f"4. Paste your tweet URL into the claim page",
            f"",
            f"Once claimed, run moltbook_status to confirm activation.",
        ]
        return ToolResult.ok("\n".join(output), metadata={"api_key": api_key, "claim_url": claim_url})


class MoltbookStatusTool(BaseTool):
    name = "moltbook_status"
    description = "Check Moltbook account status - whether the account is registered, claimed, and active."
    parameters = {"type": "object", "properties": {}, "required": []}
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        api_key = get_api_key()
        if not api_key:
            return ToolResult.fail(
                "No Moltbook API key found. Run moltbook_register first.\n"
                f"Or set MOLTBOOK_API_KEY environment variable."
            )

        result = await _request("GET", "/agents/status", api_key=api_key)
        status = result.get("status", "unknown")
        creds = load_credentials()

        lines = [
            f"Moltbook Status",
            f"  Agent:  {creds.get('agent_name', 'unknown')}",
            f"  Status: {status}",
        ]

        if status == "pending_claim":
            lines.append(f"")
            lines.append(f"  [!] Not yet claimed. Your human needs to:")
            lines.append(f"  1. Open: {creds.get('claim_url', 'unknown')}")
            lines.append(f"  2. Verify email and post a claim tweet on X")
        elif status == "claimed":
            lines.append(f"  ok Account is active and ready to post!")

        return ToolResult.ok("\n".join(lines))


class MoltbookPostTool(BaseTool):
    name = "moltbook_post"
    description = (
        "Create a post on Moltbook. Automatically solves the AI verification challenge. "
        "Use to share thoughts, discoveries, or updates with the AI agent community."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Post title (max 300 chars)",
            },
            "content": {
                "type": "string",
                "description": "Post body text (optional)",
                "default": "",
            },
            "submolt": {
                "type": "string",
                "description": "Which community to post in (default: 'general')",
                "default": "general",
            },
        },
        "required": ["title"],
    }
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(
        self,
        title: str,
        content: str = "",
        submolt: str = "general",
        **kwargs: Any,
    ) -> ToolResult:
        api_key = get_api_key()
        if not api_key:
            return ToolResult.fail("No Moltbook API key. Run moltbook_register first.")

        payload: dict[str, Any] = {"submolt_name": submolt, "title": title}
        if content:
            payload["content"] = content

        result = await _request("POST", "/posts", api_key=api_key, json_data=payload)

        # Handle verification challenge
        if result.get("verification_required") or result.get("post", {}).get("verification"):
            verification = result.get("post", {}).get("verification", {})
            challenge = verification.get("challenge_text", "")
            v_code = verification.get("verification_code", "")

            if not challenge or not v_code:
                return ToolResult.fail(f"Verification required but missing challenge data: {result}")

            answer = solve_verification_challenge(challenge)
            if not answer:
                return ToolResult.fail(
                    f"Could not solve verification challenge: {challenge!r}\n"
                    f"Challenge requires manual solving."
                )

            # Submit answer
            verify_result = await _request("POST", "/verify", api_key=api_key, json_data={
                "verification_code": v_code,
                "answer": answer,
            })

            if not verify_result.get("success"):
                return ToolResult.fail(
                    f"Verification failed (answer={answer}): {verify_result.get('error', 'unknown')}"
                )

            post_id = verify_result.get("content_id", result.get("post", {}).get("id", ""))
            return ToolResult.ok(
                f"Posted to m/{submolt}: '{title}'\n"
                f"Post ID: {post_id}\n"
                f"Verification solved: {challenge!r} → {answer}\n"
                f"URL: https://www.moltbook.com/post/{post_id}",
                metadata={"post_id": post_id},
            )

        # No verification needed (trusted agent)
        post_id = result.get("post", {}).get("id", "")
        return ToolResult.ok(
            f"Posted to m/{submolt}: '{title}'\n"
            f"Post ID: {post_id}\n"
            f"URL: https://www.moltbook.com/post/{post_id}",
            metadata={"post_id": post_id},
        )


class MoltbookFeedTool(BaseTool):
    name = "moltbook_feed"
    description = (
        "Read the Moltbook feed - see what other AI agents are posting and discussing. "
        "Returns recent posts with titles, authors, and vote counts."
    )
    parameters = {
        "type": "object",
        "properties": {
            "sort": {
                "type": "string",
                "enum": ["hot", "new", "top", "rising"],
                "description": "How to sort posts",
                "default": "hot",
            },
            "submolt": {
                "type": "string",
                "description": "Filter to a specific community (optional)",
                "default": "",
            },
            "limit": {
                "type": "integer",
                "description": "Number of posts to return (default: 10)",
                "default": 10,
            },
        },
        "required": [],
    }
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(
        self,
        sort: str = "hot",
        submolt: str = "",
        limit: int = 10,
        **kwargs: Any,
    ) -> ToolResult:
        api_key = get_api_key()

        params: dict[str, Any] = {"sort": sort, "limit": min(limit, 25)}
        if submolt:
            params["submolt"] = submolt

        result = await _request("GET", "/posts", api_key=api_key, params=params)

        posts = result.get("posts", [])
        if not posts:
            return ToolResult.ok("No posts found.")

        lines = [f"Moltbook feed ({sort}){f' - m/{submolt}' if submolt else ''}:\n"]
        for i, post in enumerate(posts[:limit], 1):
            author = post.get("author", {}).get("name", "unknown")
            title = post.get("title", "")
            upvotes = post.get("upvotes", 0)
            comments = post.get("comment_count", 0)
            sub = post.get("submolt", {}).get("name", "general")
            post_id = post.get("id", "")
            lines.append(f"{i}. [{sub}] {title}")
            lines.append(f"   by {author} | ↑{upvotes} | 💬{comments} | id:{post_id}")
            if post.get("content"):
                preview = post["content"][:100].replace("\n", " ")
                lines.append(f"   {preview}...")
            lines.append("")

        return ToolResult.ok("\n".join(lines), metadata={"post_count": len(posts)})


class MoltbookCommentTool(BaseTool):
    name = "moltbook_comment"
    description = "Add a comment to a Moltbook post. Automatically solves AI verification challenges."
    parameters = {
        "type": "object",
        "properties": {
            "post_id": {
                "type": "string",
                "description": "ID of the post to comment on",
            },
            "content": {
                "type": "string",
                "description": "Comment text",
            },
        },
        "required": ["post_id", "content"],
    }
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(self, post_id: str, content: str, **kwargs: Any) -> ToolResult:
        api_key = get_api_key()
        if not api_key:
            return ToolResult.fail("No Moltbook API key. Run moltbook_register first.")

        result = await _request(
            "POST", f"/posts/{post_id}/comments",
            api_key=api_key,
            json_data={"content": content},
        )

        # Handle verification
        if result.get("verification_required") or result.get("comment", {}).get("verification"):
            verification = result.get("comment", {}).get("verification", {})
            challenge = verification.get("challenge_text", "")
            v_code = verification.get("verification_code", "")

            answer = solve_verification_challenge(challenge)
            if not answer:
                return ToolResult.fail(f"Could not solve challenge: {challenge!r}")

            verify_result = await _request("POST", "/verify", api_key=api_key, json_data={
                "verification_code": v_code,
                "answer": answer,
            })

            if not verify_result.get("success"):
                return ToolResult.fail(f"Verification failed: {verify_result.get('error')}")

            return ToolResult.ok(f"Comment posted on post {post_id}. Verification solved: {answer}")

        if result.get("error"):
            return ToolResult.fail(result["error"])

        return ToolResult.ok(f"Comment posted on post {post_id}.")


class MoltbookSearchTool(BaseTool):
    name = "moltbook_search"
    description = (
        "Semantically search Moltbook posts and comments. "
        "Uses AI-powered search - describe what you're looking for in natural language."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "What to search for (natural language works best)",
            },
            "type": {
                "type": "string",
                "enum": ["all", "posts", "comments"],
                "description": "What to search",
                "default": "posts",
            },
            "limit": {
                "type": "integer",
                "description": "Max results (default: 10)",
                "default": 10,
            },
        },
        "required": ["query"],
    }
    permissions = {Permission.NETWORK}
    tags = ["social", "moltbook"]

    async def execute(
        self,
        query: str,
        type: str = "posts",
        limit: int = 10,
        **kwargs: Any,
    ) -> ToolResult:
        api_key = get_api_key()

        result = await _request("GET", "/search", api_key=api_key, params={
            "q": query, "type": type, "limit": min(limit, 20),
        })

        results = result.get("results", [])
        if not results:
            return ToolResult.ok(f"No results for: {query}")

        lines = [f"Moltbook search: '{query}'\n"]
        for r in results:
            author = r.get("author", {}).get("name", "unknown")
            title = r.get("title") or r.get("content", "")[:80]
            similarity = r.get("similarity", 0)
            post_id = r.get("post_id", r.get("id", ""))
            lines.append(f"- {title}")
            lines.append(f"  by {author} | similarity: {similarity:.0%} | id:{post_id}")
            lines.append("")

        return ToolResult.ok("\n".join(lines))
