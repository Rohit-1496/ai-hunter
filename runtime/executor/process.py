"""
Phase 5 Real Tactical Executor.

Executes a validated ExecutionPlan as a local subprocess.
Implements strict process limits (timeout, output capture).
NEVER uses shell=True.

Phase A final hardening:
- Child environment is always built explicitly (never inherited as-is),
  with proxy variables stripped so HTTP_PROXY/ALL_PROXY cannot divert
  traffic around SSRF validation and DNS pinning.
"""

import os
import signal
import subprocess
import time
import secrets
from pathlib import Path
from typing import Any
from runtime.executor.interface import TacticalExecutorInterface, ExecutionResult
from runtime.executor.planner import ExecutionPlan

ALLOWED_TOOL_BINARIES = frozenset({
    "curl", "dig", "python", "python3", "nmap", "whois", "openssl",
})

APPROVED_SYSTEM_BIN_DIRS = frozenset({
    Path("/bin"),
    Path("/usr/bin"),
    Path("/usr/local/bin"),
})

def validate_binary_path(binary_path: str) -> bool:
    """
    Validate that the binary is allowlisted and free of traversal/metacharacters.
    Enforces that qualified paths must reside in approved system directories
    and cannot use relative paths or directory traversal.
    """
    if not isinstance(binary_path, str) or not binary_path:
        return False
    b = binary_path.strip()
    forbidden = (";", "|", "&", "$", chr(96), chr(10), chr(13), chr(0))
    if any(c.isspace() or c in forbidden for c in b):
        return False
    if ".." in b:
        return False
    p = Path(b)
    if "/" in b or chr(92) in b:
        if not p.is_absolute():
            return False  # Disallow relative path execution (e.g. ./curl, ../bin/curl)
        if p.parent not in APPROVED_SYSTEM_BIN_DIRS:
            return False  # Disallow execution outside standard system bin directories
        name = p.name.lower()
    else:
        name = b.lower()
    return name in ALLOWED_TOOL_BINARIES

def validate_working_directory(cwd_candidate: Path | str | None, workspace_root: Path) -> tuple[bool, Path, str]:
    """
    Validates that the target working directory is strictly locked inside workspace_root.
    Resolves symlinks via realpath to prevent workspace traversal or escaping.
    """
    try:
        resolved_ws = Path(os.path.realpath(workspace_root))
        if not cwd_candidate:
            return True, resolved_ws, ""
        resolved_cwd = Path(os.path.realpath(cwd_candidate))
        if resolved_cwd != resolved_ws and resolved_ws not in resolved_cwd.parents:
            return False, resolved_ws, f"WORKING_DIRECTORY_OUTSIDE_WORKSPACE:{resolved_cwd}"
        if not resolved_cwd.is_dir():
            return False, resolved_ws, f"WORKING_DIRECTORY_NOT_A_DIR:{resolved_cwd}"
        return True, resolved_cwd, ""
    except Exception as e:
        return False, Path(os.path.realpath(workspace_root)), f"WORKING_DIRECTORY_ERROR:{e}"


def terminate_process_tree(proc: subprocess.Popen, sig: int = signal.SIGKILL, graceful_timeout: float = 0.5) -> None:
    """Kill process group to ensure child and all spawned descendants are terminated gracefully then forcefully."""
    try:
        pgid = os.getpgid(proc.pid)
        if sig == signal.SIGKILL:
            try:
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(min(0.2, graceful_timeout))
            except Exception:
                pass
            os.killpg(pgid, signal.SIGKILL)
        else:
            os.killpg(pgid, sig)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

# Environment keys that would redirect outbound traffic (SSRF/pin bypass).
_PROXY_ENV_KEYS = (
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "rsync_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "RSYNC_PROXY",
    "no_proxy", "NO_PROXY",
)

# Dangerous linker/interpreter env vars — stripped unconditionally.
# These can be used to inject code into the child process (CVE-class issues).
_DANGEROUS_ENV_KEYS: frozenset[str] = frozenset({
    # Dynamic linker & interpreter execution hooks
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE", "PYTHONHOME",
    "PERL5LIB", "PERLLIB", "RUBYLIB", "NODE_PATH", "NODE_OPTIONS",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    # Shell configuration & command hooks
    "BASH_ENV", "ENV", "PROMPT_COMMAND", "CDPATH", "IFS",
    # SSH & Git execution hijacking
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM", "GIT_SSH", "GIT_SSH_COMMAND",
    # Cloud and API credentials
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
    "HUNTER_CHECKPOINT_KEY", "HUNTER_EVIDENCE_KEY",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
    "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "KUBECONFIG",
})

def _child_preexec() -> None:
    """Pre-exec hook executed in child process context immediately before execve."""
    # 1. PR_SET_NO_NEW_PRIVS (Linux): prevents any privilege escalation via setuid/setgid
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        libc.prctl(38, 1, 0, 0, 0)
    except Exception:
        pass
    
    # 2. Resource limits: core dump restriction (protect memory & secrets)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    # 3. File descriptor bound (prevent socket/fd exhaustion attacks)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except Exception:
        pass

    # 4. Process count bound (prevent fork bombs)
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        limit = min(512, hard)
        resource.setrlimit(resource.RLIMIT_NPROC, (limit, hard))
    except Exception:
        pass

    # 5. File size creation bound (50 MB limit to prevent disk exhaustion)
    try:
        import resource
        max_fsize = 50 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize, max_fsize))
    except Exception:
        pass


def build_child_environment(plan_env: dict[str, str] | None = None) -> dict[str, str]:
    """
    Build a safe child process environment.

    Starts from a minimal inherited environment (PATH, HOME, locale, SSL
    certs) with proxy variables removed, then applies plan.environment
    (also stripped of proxy keys). Returns a full mapping — never None —
    so Popen never silently inherits ambient proxy settings.
    """
    keep_prefixes = ("PATH", "HOME", "USER", "LANG", "LC_", "SSL", "CURL", "DIG", "TZ")
    # Lower-case dangerous key set for case-insensitive comparisons
    _dangerous_lower = {k.lower() for k in _DANGEROUS_ENV_KEYS}
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in _PROXY_ENV_KEYS or key.lower() in {k.lower() for k in _PROXY_ENV_KEYS}:
            continue
        if key in _DANGEROUS_ENV_KEYS or key.lower() in _dangerous_lower:
            continue  # Strip dangerous linker/interpreter/credential vars
        if any(key == p or key.startswith(p) for p in keep_prefixes):
            env[key] = value
    ALLOWED_PLAN_ENV_EXACT = frozenset({
        "SAFE", "SAFE_DATA",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "TERM",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HTTP_TIMEOUT",
        "CONNECT_TIMEOUT", "HUNTER_TOOL_MODE", "PYTHONIOENCODING",
    })
    ALLOWED_PLAN_ENV_PREFIXES = ("HUNTER_SAFE_", "SAFE_", "CURL_", "DIG_")

    if plan_env:
        for raw_k, raw_v in plan_env.items():
            k_str = str(raw_k).strip()
            # Enforce strict positive allowlist and identifier format
            if not k_str.isidentifier():
                continue
            if k_str in _PROXY_ENV_KEYS or k_str.lower() in {k.lower() for k in _PROXY_ENV_KEYS}:
                continue
            if k_str in _DANGEROUS_ENV_KEYS or k_str.lower() in _dangerous_lower:
                continue  # Refuse dangerous keys from execution plans
            if k_str in ALLOWED_PLAN_ENV_EXACT or any(k_str.startswith(p) for p in ALLOWED_PLAN_ENV_PREFIXES):
                env[k_str] = str(raw_v)
    # Ensure PATH is strictly sanitized: reject relative paths and current working dir
    raw_path = env.get("PATH", "/usr/bin:/bin")
    safe_path_parts = [
        p for p in raw_path.split(os.pathsep)
        if p and os.path.isabs(p) and p != "." and ".." not in p
    ]
    env["PATH"] = os.pathsep.join(safe_path_parts) if safe_path_parts else "/usr/bin:/bin"
    return env


class ProcessExecutor(TacticalExecutorInterface):
    def __init__(self, workspace_root: Path, output_limit_bytes: int = 10 * 1024 * 1024):
        self._workspace_root = workspace_root
        self._raw_dir = self._workspace_root / "workspace" / "raw"
        self._output_limit = output_limit_bytes
        self.mock_responses: dict[str, Any] = {}
        
    def execute(self, plan: Any) -> ExecutionResult:
        """
        Executes the plan securely. 
        argv is fully structured. Shell is explicitly False.
        """
        if hasattr(plan, "id") and plan.id in self.mock_responses:
            return self.mock_responses[plan.id]
        if hasattr(plan, "action_id") and plan.action_id in self.mock_responses:
            return self.mock_responses[plan.action_id]
            
        if not isinstance(plan, ExecutionPlan):
            # Fallback for CandidateAction in mock testing
            return ExecutionResult(
                execution_id=f"EXEC-{secrets.token_hex(4)}",
                mission_id="mock_mission",
                action_id=getattr(plan, "id", "mock_action"),
                tool_id="mock_tool",
                status="COMPLETED",
                stdout_reference="",
                raw_output=""
            )
            
        start_time = time.time()
        
        # Build command array (binary + arguments)
        cmd = [plan.binary_path] + plan.validated_arguments
        
        # Setup streaming path
        mission_raw_dir = self._raw_dir / plan.mission_id / "execution"
        mission_raw_dir.mkdir(parents=True, exist_ok=True)
        evidence_id = f"EVID-{secrets.token_hex(4).upper()}"
        file_path = mission_raw_dir / f"{evidence_id}.txt"
        
        try:
            # We explicitly do NOT use shell=True.
            # Stream stdout and stderr combined directly to disk.
            with file_path.open("wb") as f:
                # Binary allowlisting check before spawn
                if not validate_binary_path(plan.binary_path):
                    return ExecutionResult(
                        execution_id=plan.execution_id,
                        mission_id=plan.mission_id,
                        action_id=plan.action_id,
                        tool_id=plan.tool_id,
                        status="FAILED",
                        started_at=str(start_time),
                        finished_at=str(time.time()),
                        duration_sec=0.0,
                        exit_code=1,
                        stdout_reference="",
                        stderr_reference="",
                        error_type="UNAPPROVED_BINARY"
                    )

                # Binary-specific execution safety: disallow arbitrary interpreter execution and dangerous command execution
                bin_name = Path(plan.binary_path).name.lower()
                if bin_name in ("python", "python3"):
                    dangerous_tokens = ("os.system", "subprocess", "pty", "/bin/sh", "/bin/bash", "eval(", "exec(")
                    is_dangerous = any(any(tok in str(a) for tok in dangerous_tokens) for a in plan.validated_arguments)
                    is_prod = os.environ.get("HUNTER_ENV") == "production" or os.environ.get("HUNTER_AUTH_MODE") == "production"
                    if is_dangerous or is_prod:
                        return ExecutionResult(
                            execution_id=plan.execution_id,
                            mission_id=plan.mission_id,
                            action_id=plan.action_id,
                            tool_id=plan.tool_id,
                            status="FAILED",
                            started_at=str(start_time),
                            finished_at=str(time.time()),
                            duration_sec=0.0,
                            exit_code=1,
                            stdout_reference="",
                            stderr_reference="",
                            error_type="ARBITRARY_CODE_EXECUTION_BLOCKED"
                        )

                # Argument array validation (Phase B)
                for arg in plan.validated_arguments:
                    if not isinstance(arg, str):
                        return ExecutionResult(
                            execution_id=plan.execution_id,
                            mission_id=plan.mission_id,
                            action_id=plan.action_id,
                            tool_id=plan.tool_id,
                            status="FAILED",
                            started_at=str(start_time),
                            finished_at=str(time.time()),
                            duration_sec=0.0,
                            exit_code=1,
                            stdout_reference="",
                            stderr_reference="",
                            error_type="INVALID_ARGUMENT_TYPE"
                        )
                    if "\x00" in arg:
                        return ExecutionResult(
                            execution_id=plan.execution_id,
                            mission_id=plan.mission_id,
                            action_id=plan.action_id,
                            tool_id=plan.tool_id,
                            status="FAILED",
                            started_at=str(start_time),
                            finished_at=str(time.time()),
                            duration_sec=0.0,
                            exit_code=1,
                            stdout_reference="",
                            stderr_reference="",
                            error_type="ARGUMENT_CONTAINS_NULL_BYTE"
                        )

                req_cwd = getattr(plan, "working_directory", None)
                valid_cwd, safe_cwd, cwd_err = validate_working_directory(req_cwd, self._workspace_root)
                if not valid_cwd:
                    return ExecutionResult(
                        execution_id=plan.execution_id,
                        mission_id=plan.mission_id,
                        action_id=plan.action_id,
                        tool_id=plan.tool_id,
                        status="FAILED",
                        started_at=str(start_time),
                        finished_at=str(time.time()),
                        duration_sec=0.0,
                        exit_code=1,
                        stdout_reference="",
                        stderr_reference="",
                        error_type=cwd_err
                    )

                cwd_dir = str(safe_cwd)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=build_child_environment(plan.environment),
                    cwd=cwd_dir,
                    close_fds=True,
                    start_new_session=True,
                    shell=False,
                    preexec_fn=_child_preexec,
                )
                
                import threading
                
                limit_exceeded = False
                
                def stream_output(proc, file_obj):
                    nonlocal limit_exceeded
                    bytes_written = 0
                    while True:
                        try:
                            chunk = proc.stdout.read(4096)
                        except Exception:
                            break
                        if not chunk:
                            break
                            
                        if bytes_written + len(chunk) > self._output_limit:
                            file_obj.write(chunk[:self._output_limit - bytes_written])
                            file_obj.write(b"\n...[TRUNCATED BY EXECUTOR LIMIT]...\n")
                            limit_exceeded = True
                            terminate_process_tree(proc, signal.SIGKILL)
                            break
                            
                        file_obj.write(chunk)
                        bytes_written += len(chunk)

                t = threading.Thread(target=stream_output, args=(process, f))
                t.daemon = True
                t.start()
                
                status = "COMPLETED"
                try:
                    process.wait(timeout=plan.timeout)
                except subprocess.TimeoutExpired:
                    terminate_process_tree(process, signal.SIGKILL)
                    f.write(b"\n...[TIMEOUT KILLED]...\n")
                    status = "TIMEOUT"
                    try:
                        process.wait(timeout=2)
                    except Exception:
                        pass
                
                t.join(timeout=2)
                
            end_time = time.time()
            if status != "TIMEOUT":
                if process.returncode != 0:
                    status = "FAILED"
                if limit_exceeded:
                    status = "COMPLETED_TRUNCATED"
                
            return ExecutionResult(
                execution_id=plan.execution_id,
                mission_id=plan.mission_id,
                action_id=plan.action_id,
                tool_id=plan.tool_id,
                status=status,
                started_at=str(start_time),
                finished_at=str(end_time),
                duration_sec=end_time - start_time,
                exit_code=process.returncode,
                stdout_reference=str(file_path), # Phase 5.1: Path to streamed file
                stderr_reference="",
                error_type=None
            )
            
        except Exception as e:
            end_time = time.time()
            return ExecutionResult(
                execution_id=plan.execution_id,
                mission_id=plan.mission_id,
                action_id=plan.action_id,
                tool_id=plan.tool_id,
                status="FAILED",
                started_at=str(start_time),
                finished_at=str(end_time),
                duration_sec=end_time - start_time,
                exit_code=None,
                stdout_reference="",
                stderr_reference="",
                error_type=str(e)
            )
