"""
runtime/executor/argument_validator.py
Phase 5.2 Multi-Layer Argument Security & Tool-Specific Schema Validation.

Enforces:
- Defense-in-depth shell metacharacter and command substitution filtering.
- Unicode lookalike character detection (fullwidth and homoglyph operators).
- Option injection and dangerous flag neutralization.
- Tool-specific argument schemas for curl, dig, nmap, whois, and openssl.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Sequence

# Critical shell execution / command injection operators
_SHELL_INJECTION_TOKENS = (
    ";", "&&", "||", "|", "`", "$(", "${", ">", ">>", "<",
    "\n", "\r", "\0"
)

# Unicode lookalike operators commonly used to evade naive ASCII filters
_UNICODE_LOOKALIKES = {
    "\uff1b": ";",   # Fullwidth semicolon
    "\uff06": "&",   # Fullwidth ampersand
    "\uff5c": "|",   # Fullwidth vertical line
    "\uff04": "$",   # Fullwidth dollar sign
    "\uff1e": ">",   # Fullwidth greater-than
    "\uff1c": "<",   # Fullwidth less-than
    "\uff40": "`",   # Fullwidth grave accent
    "\u02cb": "`",   # Modifier letter grave accent
    "\u2010": "-",   # Hyphen
    "\u2012": "-",   # Figure dash
    "\u2013": "-",   # En dash
    "\u2014": "-",   # Em dash
    "\ufe58": "-",   # Small em dash
    "\uff0d": "-",   # Fullwidth hyphen-minus
}

# RFC 7230 HTTP method token
_VALID_HTTP_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"})

# Approved dig options
_APPROVED_DIG_OPTIONS = frozenset({
    "+short", "+nocmd", "+noall", "+answer", "+stats", "+identify", "+comments",
    "+recurse", "+norecurse", "+trace", "+dnssec"
})

# Approved dig record types
_APPROVED_DNS_RECORD_TYPES = frozenset({
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
    "DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG", "ANY"
})


class ArgumentValidationError(ValueError):
    """Raised when command line arguments violate security policies."""
    pass


class ArgumentSecurityValidator:
    """Multi-layer argument validator enforcing strict structural and semantic policies."""

    @staticmethod
    def normalize_and_inspect_metacharacters(arg: str) -> tuple[bool, str]:
        """
        Inspects string for shell metacharacters and Unicode evasion.

        Returns:
            (is_safe, failure_reason)
        """
        if not isinstance(arg, str):
            return False, "ARGUMENT_NOT_STRING"

        # 1. Null-byte check
        if "\0" in arg:
            return False, "NULL_BYTE_INJECTION"

        # 2. Direct ASCII metacharacters
        for tok in _SHELL_INJECTION_TOKENS:
            if tok in arg:
                return False, f"SHELL_METACHARACTER_DETECTED:{tok!r}"

        # 3. Unicode lookalike detection
        for u_char, repl in _UNICODE_LOOKALIKES.items():
            if u_char in arg:
                return False, f"UNICODE_LOOKALIKE_EVASION:{u_char!r}->{repl!r}"

        # 4. Command substitution patterns
        if re.search(r"\$\([^\)]*\)", arg) or re.search(r"`[^`]*`", arg):
            return False, "COMMAND_SUBSTITUTION_PATTERN"

        return True, ""

    @classmethod
    def validate_tool_arguments(
        cls,
        tool_name: str,
        argv: Sequence[str],
        workspace_root: Path | str | None = None,
    ) -> tuple[bool, str]:
        """
        Performs multi-layer argument validation:
        1. General metacharacter & Unicode inspection.
        2. Tool-specific schema and option injection verification.
        """
        clean_tool = tool_name.strip().lower()

        # Step 1: Universal metacharacter inspection
        for idx, arg in enumerate(argv):
            is_safe, reason = cls.normalize_and_inspect_metacharacters(arg)
            if not is_safe:
                return False, f"ARG[{idx}]:{reason}"

        # Step 2: Tool-specific schemas
        if clean_tool == "curl":
            return cls._validate_curl_arguments(argv, workspace_root)
        elif clean_tool == "dig":
            return cls._validate_dig_arguments(argv)
        elif clean_tool == "nmap":
            return cls._validate_nmap_arguments(argv)
        elif clean_tool == "whois":
            return cls._validate_whois_arguments(argv)
        elif clean_tool == "openssl":
            return cls._validate_openssl_arguments(argv)

        return True, ""

    @classmethod
    def _validate_curl_arguments(
        cls,
        argv: Sequence[str],
        workspace_root: Path | str | None = None,
    ) -> tuple[bool, str]:
        """Validates curl arguments against option injection and dangerous flags."""
        forbidden_flags = {
            "-K", "--config",             # Arbitrary config file reading
            "-o", "--output",             # Direct output redirection to arbitrary files
            "-O", "--remote-name",        # Remote filename write
            "-T", "--upload-file",        # Arbitrary file upload/exfiltration
            "--trace", "--trace-ascii",   # Trace file output
            "--libcurl",                  # Code generation output
            "--engine",                   # OpenSSL crypto engine injection
        }

        i = 0
        while i < len(argv):
            arg = argv[i]

            # Check forbidden flags
            if arg in forbidden_flags:
                return False, f"FORBIDDEN_CURL_FLAG:{arg}"

            # Check equals-form dangerous flags (e.g., --config=/etc/passwd, --output=/etc/shadow)
            for ff in forbidden_flags:
                if ff.startswith("--") and arg.startswith(f"{ff}="):
                    return False, f"FORBIDDEN_CURL_FLAG:{arg}"

            # Check file reading in data flags (e.g. -d @/etc/passwd, --data-binary @/etc/shadow)
            if arg in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode"):
                if i + 1 < len(argv):
                    val = argv[i + 1]
                    if val.startswith("@"):
                        return False, f"FILE_READ_DATA_INJECTION:{val}"
            elif any(arg.startswith(f"{prefix}=") for prefix in ("--data", "--data-binary", "--data-raw")):
                val = arg.split("=", 1)[1]
                if val.startswith("@"):
                    return False, f"FILE_READ_DATA_INJECTION:{val}"

            # Validate HTTP method if specified via -X / --request
            if arg in ("-X", "--request"):
                if i + 1 < len(argv):
                    method = argv[i + 1].strip().upper()
                    if method not in _VALID_HTTP_METHODS:
                        return False, f"UNAPPROVED_HTTP_METHOD:{method}"

            # Validate header structure if specified via -H / --header
            if arg in ("-H", "--header"):
                if i + 1 < len(argv):
                    header = argv[i + 1]
                    if ":" not in header:
                        return False, f"MALFORMED_HTTP_HEADER:{header!r}"
                    hname, hval = header.split(":", 1)
                    if not re.match(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", hname.strip()):
                        return False, f"INVALID_HEADER_NAME:{hname!r}"
                    if any(c in hval for c in ("\r", "\n", "\0")):
                        return False, f"HEADER_VALUE_INJECTION:{hname!r}"

            i += 1

        return True, ""

    @classmethod
    def _validate_dig_arguments(cls, argv: Sequence[str]) -> tuple[bool, str]:
        """Validates dig arguments against server injection and dangerous options."""
        for arg in argv:
            # Server injection: dig @8.8.8.8 domain (prevents overriding approved resolver)
            if arg.startswith("@"):
                return False, f"SERVER_OVERRIDE_DISALLOWED:{arg}"

            # Plus options
            if arg.startswith("+"):
                base_opt = arg.split("=")[0]
                if base_opt not in _APPROVED_DIG_OPTIONS and not base_opt.startswith(("+time", "+tries")):
                    return False, f"UNAPPROVED_DIG_OPTION:{arg}"

            # File reading options
            if arg in ("-f", "-k", "-y"):
                return False, f"DISALLOWED_FILE_OPTION:{arg}"

        return True, ""

    @classmethod
    def _validate_nmap_arguments(cls, argv: Sequence[str]) -> tuple[bool, str]:
        """Validates nmap arguments to prevent arbitrary script execution and file writes."""
        forbidden_nmap_flags = {
            "--script", "--script-args", "--script-args-file",
            "-oN", "-oX", "-oS", "-oG", "-oA",  # Arbitrary output file creation
            "--stylesheet", "--datadir", "--interactive",
            "-iL", "-iR",                       # Input target file / random targets
            "--resume",
        }
        for arg in argv:
            if arg in forbidden_nmap_flags or any(arg.startswith(f"{f}=") for f in forbidden_nmap_flags if f.startswith("--")):
                return False, f"FORBIDDEN_NMAP_FLAG:{arg}"
        return True, ""

    @classmethod
    def _validate_whois_arguments(cls, argv: Sequence[str]) -> tuple[bool, str]:
        """Validates whois arguments against server injection and configuration options."""
        for arg in argv:
            if arg in ("-h", "--host"):
                return False, f"DISALLOWED_WHOIS_SERVER_OVERRIDE:{arg}"
            if arg.startswith("-") and any(c in arg for c in ("f", "k")):
                return False, f"DISALLOWED_WHOIS_OPTION:{arg}"
        return True, ""

    @classmethod
    def _validate_openssl_arguments(cls, argv: Sequence[str]) -> tuple[bool, str]:
        """Validates openssl arguments to prevent arbitrary key writing and crypto tampering."""
        forbidden_openssl_subcommands = {"ca", "req", "enc", "genrsa", "gendsa", "genpkey", "rand"}
        if argv and argv[0].lower() in forbidden_openssl_subcommands:
            return False, f"DISALLOWED_OPENSSL_SUBCOMMAND:{argv[0]}"

        forbidden_flags = {"-out", "-keyform", "-engine", "-CAfile", "-CApath"}
        for arg in argv:
            if arg in forbidden_flags:
                return False, f"FORBIDDEN_OPENSSL_FLAG:{arg}"
        return True, ""
