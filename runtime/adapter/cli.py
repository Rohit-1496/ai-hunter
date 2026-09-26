"""
Hunter CLI Adapter — Phase 1
OpenCode Integration: AGENTS.md instructions file

This module serves as the Thin Adapter between the operator and the
Hunter Runtime. In the OpenCode environment, the integration works via:

  opencode.jsonc → instructions: ["...AGENTS.md"]

The AGENTS.md file is loaded by OpenCode as system-level instructions
that define the hunter's behavior for the model. The model (Beast Brain)
reads brain.md, policy.md, and responds to commands like "hi" and
"hunter status" according to those constitutions.

THIS CLI is the LOCAL RUNNER / TEST HARNESS for the hunter runtime
Python layer. It allows direct verification that the runtime boots
correctly, directories are initialized, health is real, and persistence
survives restarts — WITHOUT requiring a live OpenCode session.

Usage:
  python -m runtime.adapter.cli
  python -m runtime.adapter.cli --once "hi"
  python -m runtime.adapter.cli --once "hunter status"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.bootstrap import HunterRuntime


BANNER = """
╔══════════════════════════════════════════════════╗
║  AI AUTONOMOUS BUG HUNTER — Runtime CLI          ║
║  Phase 1 Adapter                                 ║
╚══════════════════════════════════════════════════╝
Commands: hi  |  hunter status  |  exit / quit
"""

UNKNOWN_CMD = (
    "[Hunter] Unknown command. Available: hi | hunter status | exit"
)


def _dispatch(runtime: HunterRuntime, raw: str) -> str | None:
    """
    Route a raw user input string to the appropriate runtime handler.

    Returns:
        The response string, or None if the command requests exit.
    """
    cmd = raw.strip().lower()

    if cmd in ("exit", "quit", "q"):
        return None  # Signal to exit

    if cmd == "hi":
        return runtime.handshake()

    if cmd == "hunter status":
        return runtime.status_report()

    if cmd == "capabilities":
        from runtime.mvp.cli import handle_capabilities
        import io, contextlib
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            handle_capabilities(None)
        return f.getvalue().strip()

    if cmd.startswith("lab ") or cmd.startswith("mission "):
        import shlex, subprocess
        res = subprocess.run([sys.executable, "-m", "runtime.mvp.cli"] + shlex.split(raw), capture_output=True, text=True)
        return (res.stdout + res.stderr).strip()

    # Unrecognized
    return UNKNOWN_CMD


def run_interactive(runtime: HunterRuntime) -> None:
    """Run the interactive REPL loop."""
    print(BANNER)
    print("[Adapter] Initializing Hunter Runtime...\n")

    if not runtime.start():
        h = runtime.health()
        print(f"[FATAL] Runtime failed to start: {h.get('error', 'Unknown error')}")
        print("[FATAL] Check that the project root is correct and directories are writable.")
        sys.exit(1)

    print("[Adapter] Hunter Runtime initialized. Type 'hi' to begin.\n")

    while True:
        try:
            raw = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Adapter] Session ended.")
            break

        if not raw:
            continue

        response = _dispatch(runtime, raw)
        if response is None:
            print("[Adapter] Shutting down.")
            break

        print(f"\n{response}\n")


def run_once(runtime: HunterRuntime, command: str) -> int:
    """
    Run a single command non-interactively.

    Used by tests and CI to verify specific behaviors.
    Returns the exit code (0 = success, 1 = failure).
    """
    if not runtime.start():
        h = runtime.health()
        print(f"RUNTIME_START_FAILED: {h.get('error', 'Unknown')}", file=sys.stderr)
        return 1

    response = _dispatch(runtime, command)
    if response is None:
        print("EXIT_REQUESTED")
        return 0

    print(response)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Hunter Runtime CLI Adapter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--once",
        metavar="COMMAND",
        help='Run a single command and exit (e.g., --once "hi")',
    )
    parser.add_argument(
        "--root",
        metavar="PATH",
        help="Override the project root path",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve() if args.root else None
    runtime = HunterRuntime(project_root=root)

    if args.once:
        sys.exit(run_once(runtime, args.once))
    else:
        run_interactive(runtime)


if __name__ == "__main__":
    main()
