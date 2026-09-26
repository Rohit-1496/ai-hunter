"""
Level 5 Certification — Phase R Unit Tests: Manifest & Artifact Integrity

Tests:
- Manifest generation computes accurate SHA256 and byte sizes
- Modification of an artifact triggers integrity violation / hash mismatch
- Missing artifact triggers integrity violation
- Valid directory verifies successfully
"""

import tempfile
from pathlib import Path
import pytest
from runtime.validation.certification.integrity import CertificationManifestManager


def test_manifest_generation_and_verification():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Create test artifacts
        f1 = tmp_path / "finding_1.json"
        f1.write_text('{"finding": "test_1"}', encoding="utf-8")
        
        f2 = tmp_path / "sub" / "report.md"
        f2.parent.mkdir(parents=True)
        f2.write_text("# Test Report", encoding="utf-8")
        
        manifest_file = tmp_path / "CERTIFICATION_MANIFEST.json"
        
        # Generate manifest
        manifest = CertificationManifestManager.generate_manifest(
            directory_path=str(tmp_path),
            output_file_path=str(manifest_file),
            source_run_id="RUN-TEST-MANIFEST",
        )
        assert manifest["artifact_count"] == 2
        assert manifest_file.exists()
        
        # Verify valid manifest
        ok, errors = CertificationManifestManager.verify_manifest(
            directory_path=str(tmp_path),
            manifest_file_path=str(manifest_file),
        )
        assert ok
        assert len(errors) == 0


def test_manifest_detects_tampered_artifact():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        f1 = tmp_path / "finding_1.json"
        f1.write_text('{"finding": "original"}', encoding="utf-8")
        
        manifest_file = tmp_path / "CERTIFICATION_MANIFEST.json"
        CertificationManifestManager.generate_manifest(
            directory_path=str(tmp_path),
            output_file_path=str(manifest_file),
            source_run_id="RUN-TEST-TAMPER",
        )
        
        # Tamper with finding_1.json
        f1.write_text('{"finding": "tampered_post_hoc"}', encoding="utf-8")
        
        # Verification must fail
        ok, errors = CertificationManifestManager.verify_manifest(
            directory_path=str(tmp_path),
            manifest_file_path=str(manifest_file),
        )
        assert not ok
        assert any("Integrity violation" in e for e in errors)


def test_manifest_detects_missing_artifact():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        f1 = tmp_path / "finding_1.json"
        f1.write_text('{"finding": "original"}', encoding="utf-8")
        
        manifest_file = tmp_path / "CERTIFICATION_MANIFEST.json"
        CertificationManifestManager.generate_manifest(
            directory_path=str(tmp_path),
            output_file_path=str(manifest_file),
            source_run_id="RUN-TEST-MISSING",
        )
        
        # Delete file
        f1.unlink()
        
        # Verification must fail
        ok, errors = CertificationManifestManager.verify_manifest(
            directory_path=str(tmp_path),
            manifest_file_path=str(manifest_file),
        )
        assert not ok
        assert any("Missing artifact" in e for e in errors)
