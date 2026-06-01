"""
verifier_model.py — Mapache verifier pipeline stage

The verifier is the quality gate of the multi-model pipeline.
After the executor runs tasks and produces outputs, the verifier
checks them before they reach the user.

What it checks:
    - Did the tool actually produce useful output?
    - Does the output make sense given the task?
    - Are there signs of hallucination or fabrication?
    - Is the final response accurate and complete?
    - Should the executor retry with different args?

In pipeline mode this uses a high-quality reasoning model.
It's the last line of defense before a response goes out.

Verifier decisions:
    PASS     — output is good, send it
    RETRY    — output looks wrong, retry with hints
    FAIL     — output is clearly bad, explain why
    WARN     — output is okay but flag something suspicious
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from core.logger import get_logger
from models.model_registry import ModelRole
from models.routing_engine import RoutingEngine

logger = get_logger(__name__)


class Verdict(str, Enum):
    PASS  = "pass"
    RETRY = "retry"
    FAIL  = "fail"
    WARN  = "warn"
    SKIP  = "skip"   # verifier disabled or not applicable


@dataclass
class VerifierResult:
    verdict: Verdict
    confidence: float        # 0.0 to 1.0
    reasoning: str
    retry_hint: str = ""     # what to change on retry
    warnings: list[str] = None
    model_used: str = ""

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

    @property
    def should_pass(self) -> bool:
        return self.verdict in (Verdict.PASS, Verdict.WARN, Verdict.SKIP)

    @property
    def should_retry(self) -> bool:
        return self.verdict == Verdict.RETRY


VERIFIER_SYSTEM_PROMPT = """You are the verification module of Mapache, an autonomous security research agent.

Your job is to check whether tool outputs and agent responses are valid, accurate, and useful.

Given a task description and its output, evaluate quality and respond with ONLY valid JSON:

{
  "verdict": "pass|retry|fail|warn",
  "confidence": 0.95,
  "reasoning": "brief explanation",
  "retry_hint": "what to change if retrying (empty if pass)",
  "warnings": ["any concerns even if passing"]
}

VERDICT RULES:
- "pass"  — output is valid and answers the task
- "retry" — output looks wrong/empty/truncated, should retry
- "fail"  — output is clearly bad or tool errored fatally
- "warn"  — output is okay but something seems off

RED FLAGS that suggest retry or fail:
- Tool returned "[STUB]" or "dispatcher not connected"
- Output is empty or just whitespace
- Output says "Error:" without useful info
- Numbers/IPs in output look invented (round numbers, sequential IPs)
- Scan results showing 0 hosts when target should be reachable
- Model output contradicts the tool output

GREEN FLAGS that suggest pass:
- Output contains specific real data (actual IPs, port numbers, CVE IDs)
- Tool completed with exit code 0
- Output length is reasonable for the task
- Data is internally consistent"""


class VerifierModel:
    """
    Verification stage of the multi-model pipeline.

    Checks tool outputs before they reach the user or get
    injected back into the agent's context.
    """

    def __init__(
        self,
        routing_engine: RoutingEngine,
        model_providers: dict[str, Any],
        enabled: bool = True,
        min_confidence_threshold: float = 0.6,
    ) -> None:
        self.routing = routing_engine
        self.providers = model_providers
        self.enabled = enabled
        self.min_confidence = min_confidence_threshold
        self._call_count = 0
        self._retry_count = 0
        self._fail_count = 0

    async def verify(
        self,
        task_description: str,
        tool_name: str,
        tool_output: str,
        tool_args: Optional[dict] = None,
    ) -> VerifierResult:
        """
        Verify a tool's output against the task that requested it.

        Returns a VerifierResult with verdict and reasoning.
        """
        if not self.enabled:
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=1.0,
                reasoning="Verifier disabled",
            )

        # Fast path — obvious failures that don't need a model call
        quick_result = self._quick_check(tool_output)
        if quick_result:
            return quick_result

        self._call_count += 1

        # Route to verifier model
        decision = self.routing.route(ModelRole.VERIFIER)
        model_id = decision.model_id
        provider = self.providers.get(model_id) or next(iter(self.providers.values()), None)

        if not provider:
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=0.5,
                reasoning="No verifier model available",
            )

        # Build verification prompt
        args_str = json.dumps(tool_args or {}, separators=(",", ":"))
        user_content = (
            f"TASK: {task_description}\n"
            f"TOOL: {tool_name}\n"
            f"ARGS: {args_str}\n\n"
            f"OUTPUT:\n{tool_output[:3000]}"
        )

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            raw = await provider.chat(messages=messages, json_mode=True)
            if isinstance(raw, dict):
                content = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                content = str(raw)

            return self._parse_result(content, model_id)

        except Exception as exc:
            logger.error("Verifier model call failed: %s", exc)
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=0.5,
                reasoning=f"Verifier error: {exc}",
                model_used=model_id,
            )

    async def verify_final_response(
        self,
        user_goal: str,
        agent_response: str,
        tool_calls_made: list[str],
    ) -> VerifierResult:
        """
        Verify the agent's final response to the user.
        Checks it actually addresses the goal and doesn't hallucinate.
        """
        if not self.enabled:
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=1.0,
                reasoning="Verifier disabled",
            )

        decision = self.routing.route(ModelRole.VERIFIER)
        model_id = decision.model_id
        provider = self.providers.get(model_id) or next(iter(self.providers.values()), None)

        if not provider:
            return VerifierResult(verdict=Verdict.SKIP, confidence=0.5, reasoning="No verifier")

        tools_str = ", ".join(tool_calls_made) if tool_calls_made else "none"
        user_content = (
            f"USER GOAL: {user_goal}\n"
            f"TOOLS USED: {tools_str}\n\n"
            f"AGENT RESPONSE:\n{agent_response[:2000]}"
        )

        system = VERIFIER_SYSTEM_PROMPT + (
            "\n\nFor final response verification, also check:\n"
            "- Does the response actually address the user's goal?\n"
            "- Are all claims supported by the tools that were called?\n"
            "- Is there any information that couldn't have come from the tools used?"
        )

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]

        try:
            raw = await provider.chat(messages=messages, json_mode=True)
            if isinstance(raw, dict):
                content = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                content = str(raw)
            return self._parse_result(content, model_id)
        except Exception as exc:
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=0.5,
                reasoning=f"Verifier error: {exc}",
            )

    def _quick_check(self, output: str) -> Optional[VerifierResult]:
        """Fast rule-based checks before calling the model."""
        if not output or not output.strip():
            self._fail_count += 1
            return VerifierResult(
                verdict=Verdict.RETRY,
                confidence=0.95,
                reasoning="Empty output",
                retry_hint="Tool returned no output — check args and try again",
            )

        if "[STUB]" in output and "dispatcher not connected" in output:
            self._fail_count += 1
            return VerifierResult(
                verdict=Verdict.FAIL,
                confidence=0.99,
                reasoning="Tool dispatcher not connected",
                retry_hint="Wire up the tool dispatcher before calling tools",
            )

        if output.startswith("Error:") and len(output) < 50:
            self._retry_count += 1
            return VerifierResult(
                verdict=Verdict.RETRY,
                confidence=0.80,
                reasoning=f"Tool returned a bare error: {output}",
                retry_hint="Check tool arguments and prerequisites",
            )

        return None

    def _parse_result(self, content: str, model_id: str) -> VerifierResult:
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return VerifierResult(
                verdict=Verdict.SKIP,
                confidence=0.5,
                reasoning="Could not parse verifier response",
                model_used=model_id,
            )

        verdict_str = data.get("verdict", "pass").lower()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.PASS

        if verdict == Verdict.RETRY:
            self._retry_count += 1
        elif verdict == Verdict.FAIL:
            self._fail_count += 1

        return VerifierResult(
            verdict=verdict,
            confidence=float(data.get("confidence", 0.7)),
            reasoning=data.get("reasoning", ""),
            retry_hint=data.get("retry_hint", ""),
            warnings=data.get("warnings", []),
            model_used=model_id,
        )

    @property
    def stats(self) -> dict:
        return {
            "calls": self._call_count,
            "retries_triggered": self._retry_count,
            "failures_caught": self._fail_count,
        }
