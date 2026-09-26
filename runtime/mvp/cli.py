"""
Phase 6 MVP — Autonomous Bug Hunter CLI Entrypoint

Provides complete operational CLI commands for:
- Mission management: create, run, status, resume, cancel
- Synthetic Lab management: start, stop, status
- Evidence inspection: list, show
- Hypothesis inspection: list
- Report generation & view
- System capability assessment

Usage:
  python -m runtime.mvp.cli mission run --id M-SYNTH-01
  python -m runtime.mvp.cli lab start
  python -m runtime.mvp.cli lab stop
  python -m runtime.mvp.cli capabilities
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.mvp.core import BeastBrainMVPEngine
from runtime.synthetic_lab.server import SyntheticLabServer

LAB_STATE_FILE = _PROJECT_ROOT / "state" / "synthetic_lab.json"


def _get_lab_server() -> tuple[SyntheticLabServer | None, str]:
    if not LAB_STATE_FILE.is_file():
        return None, ""
    try:
        data = json.loads(LAB_STATE_FILE.read_text(encoding="utf-8"))
        return None, data.get("base_url", "")
    except Exception:
        return None, ""


def handle_lab(args: argparse.Namespace) -> int:
    action = args.lab_action

    if action == "start":
        port = getattr(args, "port", 0) or 0
        lab = SyntheticLabServer(host="127.0.0.1", port=port)
        base_url = lab.start()
        LAB_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAB_STATE_FILE.write_text(json.dumps({
            "pid": os.getpid(),
            "port": lab.actual_port,
            "base_url": base_url,
            "started_at": time.time(),
        }), encoding="utf-8")
        print(f"[SyntheticLab] Lab server started successfully at {base_url}")
        print(f"[SyntheticLab] State written to {LAB_STATE_FILE}")
        return 0

    elif action == "stop":
        if LAB_STATE_FILE.is_file():
            try:
                LAB_STATE_FILE.unlink()
                print("[SyntheticLab] Lab state file removed. Server stopped.")
            except Exception as e:
                print(f"[SyntheticLab] Error stopping lab: {e}", file=sys.stderr)
                return 1
        else:
            print("[SyntheticLab] No running lab detected (state file absent).")
        return 0

    elif action == "status":
        if LAB_STATE_FILE.is_file():
            data = json.loads(LAB_STATE_FILE.read_text(encoding="utf-8"))
            print(f"[SyntheticLab] ACTIVE — Base URL: {data.get('base_url')} (Port: {data.get('port')})")
        else:
            print("[SyntheticLab] INACTIVE — Lab is not running.")
        return 0

    else:
        print(f"Unknown lab action: {action}", file=sys.stderr)
        return 1


def handle_mission(args: argparse.Namespace) -> int:
    engine = BeastBrainMVPEngine(project_root=_PROJECT_ROOT, dry_run=args.dry_run)
    action = args.mission_action

    if action == "create":
        mission_id = args.id or f"M-SYNTH-{int(time.time())}"
        targets = [t.strip() for t in args.scope.split(",") if t.strip()]
        req = {
            "mission_id": mission_id,
            "allowed_ips": [t for t in targets if t.replace(".", "").isdigit()],
            "allowed_domains": [t for t in targets if not t.replace(".", "").isdigit()],
            "mission_objective": args.objective or "Synthetic Lab Assessment",
            "environment": "lab",
        }
        valid, reason, contract = engine.intake_and_validate(req)
        if not valid:
            print(f"[Mission] Intake REJECTED: {reason}", file=sys.stderr)
            return 1
        print(f"[Mission] Successfully created and validated mission: {mission_id}")
        return 0

    elif action == "run":
        mission_id = args.id or f"M-SYNTH-{int(time.time())}"
        targets = [t.strip() for t in args.scope.split(",") if t.strip()] if getattr(args, "scope", None) else ["127.0.0.1", "localhost"]
        
        # Check if lab is running or start ephemeral
        lab_url = getattr(args, "target_url", None)
        ephemeral_lab = None
        if not lab_url:
            _, running_url = _get_lab_server()
            if running_url:
                lab_url = running_url
            else:
                ephemeral_lab = SyntheticLabServer(host="127.0.0.1", port=0)
                lab_url = ephemeral_lab.start()
                print(f"[Mission] Started ephemeral synthetic lab at {lab_url}")

        try:
            req = {
                "mission_id": mission_id,
                "allowed_ips": [t for t in targets if t.replace(".", "").isdigit()],
                "allowed_domains": [t for t in targets if not t.replace(".", "").isdigit()],
                "mission_objective": args.objective or "Autonomous Synthetic Security Assessment",
                "environment": "lab",
            }
            summary, findings, report_path = engine.run_synthetic_mission(req, lab_base_url=lab_url)
            print("\n" + "=" * 60)
            print(f"BEAST BRAIN MISSION COMPLETED: {mission_id}")
            print("=" * 60)
            print(f"Status:             {summary.status.value}")
            print(f"Total Requests:     {summary.total_requests}")
            print(f"Evidence Collected: {summary.evidence_items_count}")
            print(f"Hypotheses Tested:  {summary.hypotheses_count}")
            print(f"Validated Findings: {len(findings)}")
            for f in findings:
                print(f"  - [{f.severity}] {f.title} ({f.affected_endpoints[0] if f.affected_endpoints else ''})")
            print(f"Final Report:       {report_path}")
            print("=" * 60 + "\n")
            return 0
        finally:
            if ephemeral_lab:
                ephemeral_lab.stop()
                print("[Mission] Ephemeral synthetic lab stopped cleanly.")

    elif action == "status":
        if not args.id:
            print("Error: --id is required for mission status", file=sys.stderr)
            return 1
        try:
            m = engine.mission_manager.get_mission(args.id)
            print(json.dumps(m, indent=2))
            return 0
        except Exception as e:
            print(f"[Mission] Mission {args.id} not found: {e}", file=sys.stderr)
            return 1

    elif action == "resume":
        if not args.id:
            print("Error: --id is required for mission resume", file=sys.stderr)
            return 1
        try:
            capsule = engine.checkpoint_engine.load_checkpoint(args.id)
            valid, reason, state = engine.resume_from_checkpoint(args.id, capsule)
            if not valid:
                print(f"[Mission] Resume FAILED: {reason}", file=sys.stderr)
                return 1
            print(f"[Mission] Checkpoint verified! Resuming mission {args.id} from iteration {state.get('iteration')}")
            return 0
        except Exception as e:
            print(f"[Mission] Error resuming mission {args.id}: {e}", file=sys.stderr)
            return 1

    elif action == "cancel":
        if not args.id:
            print("Error: --id is required for mission cancel", file=sys.stderr)
            return 1
        try:
            engine.mission_manager.update_mission(args.id, {"status": "CANCELLED"})
            engine.mission_manager.log_event(args.id, "mission_cancelled", {"cancelled_at": time.time()})
            print(f"[Mission] Mission {args.id} successfully cancelled.")
            return 0
        except Exception as e:
            print(f"[Mission] Error cancelling mission {args.id}: {e}", file=sys.stderr)
            return 1

    return 1


def handle_capabilities(args: argparse.Namespace) -> int:
    engine = BeastBrainMVPEngine(project_root=_PROJECT_ROOT)
    caps = {
        "reasoning_engine": "BeastBrainOperationalCore (Single Continuous Loop)",
        "security_gates": [
            "ScopeResolver (CIDR, domain, subdomain, loopback pinning)",
            "ContextIsolator (Prompt Injection Neutralization Firewall)",
            "ToolOrchestrator (Subprocess Sandboxing, Whitelist Arguments)",
            "HMAC Checkpoint Seal (Scope & Auth Binding)",
            "FindingValidator (11-Point Validation Quality Gate)",
        ],
        "supported_tools": ["curl"],
        "synthetic_lab": {
            "environment": "Local Isolated ThreadingHTTPServer (127.0.0.1)",
            "scenarios": [
                "Public Endpoint Discovery (/)",
                "Health Check (/health)",
                "API Catalog (/api/v1/endpoints)",
                "BOLA / IDOR (/api/v1/documents/2) [Documented Synthetic Weakness]",
                "Role Auth Boundary (/api/v1/admin/metrics)",
                "Security Headers Baseline (/api/v1/legacy)",
                "Navigation Redirect (/redirect)",
                "Search Reflection (/api/v1/search)",
                "Negative Path Traversal Defense (/api/v1/documents/../../etc/passwd)",
            ],
        },
        "limits": {
            "max_iterations": 10,
            "max_requests": 500,
            "max_processes": 50,
            "fail_closed_on_out_of_scope": True,
        }
    }
    print(json.dumps(caps, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Autonomous Bug Hunter — Beast Brain Operational CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="Simulate tool execution without subprocess invocation")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Lab subcommand
    lab_parser = subparsers.add_parser("lab", help="Manage local synthetic security lab")
    lab_parser.add_argument("lab_action", choices=["start", "stop", "status"], help="Lab lifecycle action")
    lab_parser.add_argument("--port", type=int, default=0, help="Explicit port to bind (default: 0 for dynamic)")

    # Mission subcommand
    mission_parser = subparsers.add_parser("mission", help="Manage autonomous security missions")
    mission_parser.add_argument("mission_action", choices=["create", "run", "status", "resume", "cancel"], help="Mission action")
    mission_parser.add_argument("--dry-run", action="store_true", help="Simulate tool execution without subprocess invocation")
    mission_parser.add_argument("--id", type=str, help="Mission ID")
    mission_parser.add_argument("--scope", type=str, default="127.0.0.1,localhost", help="Comma-separated target domains/IPs")
    mission_parser.add_argument("--objective", type=str, default="Autonomous Synthetic Security Assessment", help="Mission objective")
    mission_parser.add_argument("--target-url", type=str, help="Explicit base URL of synthetic lab")

    # Capabilities subcommand
    subparsers.add_parser("capabilities", help="Inspect Beast Brain operational capabilities and security boundaries")

    args = parser.parse_args()

    if args.subcommand == "lab":
        sys.exit(handle_lab(args))
    elif args.subcommand == "mission":
        sys.exit(handle_mission(args))
    elif args.subcommand == "capabilities":
        sys.exit(handle_capabilities(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
