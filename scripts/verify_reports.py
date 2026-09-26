import re
from pathlib import Path

reports_dir = Path("/home/kali/Downloads/ai-hunter/reports")
required_files = [
    "INDEPENDENT_REPOSITORY_AUDIT_REPORT.md",
    "SECURITY_FINDINGS_REGISTER.md",
    "PHASE_B_CLAIM_VERIFICATION_MATRIX.md",
    "ADVERSARIAL_TEST_RESULTS.md",
    "DEPLOYMENT_HARDENING_REPORT.md",
    "DEPLOYMENT_SECURITY_CHECKLIST.md",
    "RESIDUAL_RISK_REGISTER_UPDATED.md",
    "REMEDIATION_CHANGE_MANIFEST.md",
    "REGRESSION_TEST_REPORT.md",
    "PRE_PHASE_C_READINESS_REPORT.md",
    "README.md",
]

print(f"{'Report File':<42} | {'Size (Bytes)':<12} | {'Headings':<8} | {'No Secrets':<10} | {'Status'}")
print("-" * 88)

for fname in required_files:
    fpath = reports_dir / fname
    assert fpath.exists(), f"File {fname} does not exist!"
    size = fpath.stat().st_size
    assert size > 0, f"File {fname} is empty!"
    
    text = fpath.read_text(encoding="utf-8")
    headings = len(re.findall(r"^#+\s+", text, re.MULTILINE))
    assert headings > 0, f"File {fname} has no markdown headings!"
    
    # Check for accidental secrets
    secret_patterns = [r"AKIA[0-9A-Z]{16}", r"-----BEGIN RSA PRIVATE KEY-----", r"ghp_[A-Za-z0-9_]{36}"]
    has_secret = any(re.search(pat, text, re.IGNORECASE) for pat in secret_patterns)
    assert not has_secret, f"File {fname} contains suspicious secrets!"
    
    print(f"{fname:<42} | {size:<12} | {headings:<8} | {'CONFIRMED':<10} | VERIFIED")

print("-" * 88)
print("All 11 reports successfully verified through direct disk readback!")
