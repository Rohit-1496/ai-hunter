import os
from pathlib import Path

reports_dir = Path("/home/kali/Downloads/ai-hunter/docs/reports")
required_reports = [
    "PRE_PHASE_C_FINAL_RECONCILIATION_REPORT.md",
    "DEPLOYMENT_GATE_FINAL_VERIFICATION.md",
    "SECURITY_FINDINGS_RECONCILIATION_FINAL.md",
    "ADVERSARIAL_REGRESSION_FINAL_VERIFICATION.md",
    "PHASE_C_SECURITY_BOUNDARY_REQUIREMENTS.md",
    "PRE_PHASE_C_FINAL_READINESS_DECISION.md",
]

print(f"{'Report File':<45} | {'Size (B)':<10} | {'Lines':<8} | {'Existence & Location'}")
print("-" * 85)

for fname in required_reports:
    fpath = reports_dir / fname
    assert fpath.exists(), f"Missing file: {fname}"
    assert fpath.is_file(), f"Not a regular file: {fname}"
    assert fpath.parent.resolve() == reports_dir.resolve(), f"Wrong location: {fpath}"
    
    content = fpath.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, f"Empty content in {fname}"
    
    line_count = len(content.splitlines())
    size = fpath.stat().st_size
    print(f"{fname:<45} | {size:<10} | {line_count:<8} | VERIFIED inside docs/reports/")

print("-" * 85)
print("All 6 reports verified existing, located strictly in docs/reports/, and non-empty!")
