"""
runtime/tools/output_pipeline.py
Phase 6.5 Output Normalization, Context Firewall, and Evidence Pipeline.

Enforces:
- Untrusted output processing and sandboxing.
- Rejection of prompt injection instructions that attempt to mutate mission state or policy.
- Extraction of structured indicators (HTTP status, headers, body hashes).
- Preservation of raw output hashes (SHA-256) and evidence provenance.
- Production of compact, forensic-grade normalized evidence items.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from runtime.context.isolation import ContextIsolator
from runtime.tools.execution_adapter import ExecutionResult
from runtime.tools.models import ToolActionStatus


@dataclass
class NormalizedEvidence:
    """Structured evidence produced from validated tool execution."""
    evidence_id: str
    action_id: str
    mission_id: str
    tool_id: str
    target: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    raw_output_sha256: str = ""
    prompt_injection_flag: bool = False
    evidence_type: str = "HTTP_PROBE_OBSERVATION"
    observation_summary: str = ""
    is_contradictory: bool = False
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "action_id": self.action_id,
            "mission_id": self.mission_id,
            "tool_id": self.tool_id,
            "target": self.target,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_snippet": self.body_snippet,
            "raw_output_sha256": self.raw_output_sha256,
            "prompt_injection_flag": self.prompt_injection_flag,
            "evidence_type": self.evidence_type,
            "observation_summary": self.observation_summary,
            "is_contradictory": self.is_contradictory,
            "provenance": self.provenance,
            "created_at": self.created_at,
        }


class ToolOutputPipeline:
    """
    Transforms untrusted tool execution output into structured, safe evidence items.
    """

    def __init__(
        self,
        mission_id: str,
        context_isolator: ContextIsolator | None = None,
    ) -> None:
        self.mission_id = mission_id
        self.context_isolator = context_isolator or ContextIsolator()

    def process_output(
        self,
        result: ExecutionResult,
        target: str,
        tool_id: str,
    ) -> NormalizedEvidence:
        """
        Safely process raw tool execution output into normalized evidence.
        """
        # Generate deterministic evidence ID
        raw_combined = f"{result.action_id}:{result.raw_hash}:{tool_id}"
        evidence_id = f"EV-{hashlib.sha256(raw_combined.encode()).hexdigest()[:16]}"

        status_code = 0
        headers: dict[str, str] = {}
        body = ""

        # Parse HTTP response if present
        if result.stdout:
            stdout_text = result.stdout
            # Split headers and body
            if "\r\n\r\n" in stdout_text:
                head_part, body_part = stdout_text.split("\r\n\r\n", 1)
            elif "\n\n" in stdout_text:
                head_part, body_part = stdout_text.split("\n\n", 1)
            else:
                head_part, body_part = stdout_text, ""

            # Extract status code
            status_match = re.search(r"HTTP/\d\.\d\s+(\d{3})", head_part)
            if status_match:
                status_code = int(status_match.group(1))

            # Extract headers
            for line in head_part.splitlines():
                if ":" in line and not line.startswith("HTTP/"):
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = body_part.strip()
        elif result.stderr:
            body = f"STDERR: {result.stderr.strip()}"

        # Context Firewall isolation
        isolated_envelope = self.context_isolator.isolate(
            content=body,
            source_component="tool_output_pipeline",
            provenance={"mission_id": self.mission_id, "action_id": result.action_id},
        )

        prompt_injection = (
            result.prompt_injection_detected or
            getattr(isolated_envelope, "prompt_injection_detected", False)
        )

        # Truncate snippet for evidence summary (compact context preservation)
        body_snippet = body[:500] if len(body) > 500 else body

        # Determine observation summary
        if result.status == ToolActionStatus.TIMED_OUT:
            observation_summary = f"Tool execution timed out on {target}"
            is_contradictory = True
        elif result.status == ToolActionStatus.FAILED:
            observation_summary = f"Tool execution failed with exit code {result.exit_code}: {result.stderr[:100]}"
            is_contradictory = True
        elif status_code == 200:
            if "CONFIDENTIAL_REPORT_IDOR_FLAG" in body:
                observation_summary = f"Confirmed unauthorized object access (IDOR) on {target}"
                is_contradictory = False
            elif "Server:" in result.stdout and not ("Strict-Transport-Security" in headers or "Content-Security-Policy" in headers):
                observation_summary = f"Confirmed missing security headers on {target}"
                is_contradictory = False
            else:
                observation_summary = f"HTTP 200 OK returned from {target}"
                is_contradictory = False
        elif status_code in (401, 403):
            observation_summary = f"Access denied (HTTP {status_code}) on {target}"
            is_contradictory = False
        else:
            observation_summary = f"Tool executed with status code {status_code} on {target}"
            is_contradictory = False

        if prompt_injection:
            observation_summary += " [PROMPT_INJECTION_CONTAINED_IN_PAYLOAD]"

        return NormalizedEvidence(
            evidence_id=evidence_id,
            action_id=result.action_id,
            mission_id=self.mission_id,
            tool_id=tool_id,
            target=target,
            status_code=status_code,
            headers=headers,
            body_snippet=body_snippet,
            raw_output_sha256=result.raw_hash,
            prompt_injection_flag=prompt_injection,
            evidence_type="HTTP_PROBE_OBSERVATION",
            observation_summary=observation_summary,
            is_contradictory=is_contradictory,
            provenance={
                "action_id": result.action_id,
                "tool_id": tool_id,
                "duration_seconds": result.duration_seconds,
                "exit_code": result.exit_code,
                "output_bytes": result.output_bytes,
            },
        )
