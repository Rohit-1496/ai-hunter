"""
Production Validation & Certification Track (PVCT) — State Persistence Manager

Handles atomic disk writes, secret redaction, directory initialization,
and tamper-evident persistence for all validation runs, gates, evidence, and reports.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from runtime.validation.integrity import (
    FailClosedIntegrityError,
    canonical_json,
    compute_file_digest,
    compute_sha256,
)
from runtime.validation.models import (
    CertificationAssessment,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationRun,
)

# Regex patterns for redacting secrets before writing to disk
SECRET_PATTERNS = [
    re.compile(r'(?i)(["\']?(?:password|token|secret|api[_-]?key|auth(?:orization)?)["\']?\s*[:=]\s*["\'])([^"\']{3,})(["\'])'),
    re.compile(r'(Bearer\s+)[A-Za-z0-9_\-\.]{8,}'),
    re.compile(r'(-----BEGIN [A-Z ]+ PRIVATE KEY-----)(.*?)(-----END [A-Z ]+ PRIVATE KEY-----)', re.DOTALL),
]


def redact_sensitive_data(text_or_obj: Any) -> Any:
    """Recursively redacts secrets, credentials, and sensitive tokens."""
    if isinstance(text_or_obj, str):
        val = text_or_obj
        for pattern in SECRET_PATTERNS:
            if pattern.pattern.startswith("(?i)"):
                val = pattern.sub(r"\g<1>[REDACTED]\g<3>", val)
            elif "Bearer" in pattern.pattern:
                val = pattern.sub(r"\g<1>[REDACTED]", val)
            elif "PRIVATE KEY" in pattern.pattern:
                val = pattern.sub(r"\g<1>\n[REDACTED PRIVATE KEY]\n\g<3>", val)
        return val
    elif isinstance(text_or_obj, dict):
        redacted = {}
        for k, v in text_or_obj.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ("token", "password", "secret", "api_key", "apikey", "credential", "auth")):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v)
        return redacted
    elif isinstance(text_or_obj, list):
        return [redact_sensitive_data(item) for item in text_or_obj]
    return text_or_obj


class ValidationPersistenceManager:
    """Manages the persistence of PVCT artifacts within the validation/ root directory."""

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        self.validation_dir = self.project_root / "validation"
        self.environments_dir = self.validation_dir / "environments"
        self.benchmarks_dir = self.validation_dir / "benchmarks"
        self.benchmarks_known_dir = self.benchmarks_dir / "known"
        self.benchmarks_blind_dir = self.benchmarks_dir / "blind"
        self.benchmarks_negative_dir = self.benchmarks_dir / "negative"
        self.adversarial_dir = self.validation_dir / "adversarial"
        self.failure_injection_dir = self.validation_dir / "failure-injection"
        self.scale_dir = self.validation_dir / "scale"
        self.real_targets_dir = self.validation_dir / "real-targets"
        self.human_baseline_dir = self.validation_dir / "human-baseline"
        self.metrics_dir = self.validation_dir / "metrics"
        self.evidence_dir = self.validation_dir / "evidence"
        self.reports_dir = self.validation_dir / "reports"
        self.certification_dir = self.validation_dir / "certification"

        self.ensure_directories()

    def ensure_directories(self) -> None:
        """Scaffolds all mandatory directories required by PVCT specification."""
        dirs = [
            self.validation_dir,
            self.environments_dir,
            self.benchmarks_dir,
            self.benchmarks_known_dir,
            self.benchmarks_blind_dir,
            self.benchmarks_negative_dir,
            self.adversarial_dir,
            self.failure_injection_dir,
            self.scale_dir,
            self.real_targets_dir,
            self.human_baseline_dir,
            self.metrics_dir,
            self.evidence_dir,
            self.reports_dir,
            self.certification_dir,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def write_atomic_json(self, file_path: Path, data: Any, redact: bool = True) -> str:
        """
        Atomically writes data to disk as canonical JSON and returns its SHA256 digest.
        Uses a .tmp sibling and atomic replace to guarantee no partial writes.
        """
        file_path.parent.mkdir(parents=True, exist_ok=True)
        cleaned = redact_sensitive_data(data) if redact else data
        content = canonical_json(cleaned)
        digest = compute_sha256(content)

        tmp_path = file_path.with_suffix(f".tmp.{os.getpid()}")
        try:
            tmp_path.write_text(content, encoding="utf-8")
            tmp_path.replace(file_path)
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise FailClosedIntegrityError(f"Atomic write failed for {file_path}: {e}")

        return digest

    def write_atomic_text(self, file_path: Path, text: str, redact: bool = True) -> str:
        """Atomically writes text/markdown to disk and returns its SHA256 digest."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        cleaned = redact_sensitive_data(text) if redact else text
        digest = compute_sha256(cleaned)

        tmp_path = file_path.with_suffix(f".tmp.{os.getpid()}")
        try:
            tmp_path.write_text(cleaned, encoding="utf-8")
            tmp_path.replace(file_path)
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise FailClosedIntegrityError(f"Atomic text write failed for {file_path}: {e}")

        return digest

    def save_run(self, run: ValidationRun) -> Path:
        """Persists a complete validation run record."""
        run.compute_digest()
        path = self.reports_dir / f"{run.run_id}_run.json"
        self.write_atomic_json(path, run.to_dict())
        return path

    def load_run(self, run_id: str) -> ValidationRun | None:
        """Loads and verifies a validation run record. Fails closed on corruption."""
        path = self.reports_dir / f"{run_id}_run.json"
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            stored_digest = raw.get("run_digest", "")
            run = ValidationRun.from_dict(raw)
            computed = run.compute_digest()
            if stored_digest and stored_digest.lower() != computed.lower():
                raise FailClosedIntegrityError(f"Tamper detected in run {run_id}: {stored_digest} != {computed}")
            return run
        except Exception as e:
            raise FailClosedIntegrityError(f"Failed to load validation run {run_id}: {e}")

    def save_evidence(self, evidence: ValidationEvidence, raw_payload: str | bytes | None = None) -> Path:
        """Saves a validation evidence descriptor and optionally its raw payload."""
        evidence_file = self.evidence_dir / f"{evidence.evidence_id}.json"
        if raw_payload is not None:
            raw_file = self.evidence_dir / f"{evidence.evidence_id}.raw"
            if isinstance(raw_payload, bytes):
                raw_file.write_bytes(raw_payload)
            else:
                self.write_atomic_text(raw_file, str(raw_payload))
            evidence.artifact_path = str(raw_file.relative_to(self.project_root))
            evidence.compute_digest()

        self.write_atomic_json(evidence_file, evidence.to_dict())
        return evidence_file

    def save_certification(self, cert: CertificationAssessment) -> Path:
        """Saves an authoritative certification assessment."""
        cert.compute_digest()
        path = self.certification_dir / f"{cert.assessment_id}.json"
        self.write_atomic_json(path, cert.to_dict())
        # Also maintain canonical latest
        latest_path = self.certification_dir / "latest_certification.json"
        self.write_atomic_json(latest_path, cert.to_dict())
        return path
