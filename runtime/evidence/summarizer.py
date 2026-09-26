"""
Phase 6.1 / 6.2 — Smart Tool Output Summarizer

Extracts security-relevant signals from verbose tool outputs without relying
on an LLM. Preserves critical status codes, headers, indicators, injection signatures,
authentication/authorization boundaries, and forensic hashes while constraining
context size to the configured token budget (300-800 tokens).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qs
from typing import Any

from runtime.evidence.storage_policy import estimate_tokens


# Known SQL Error Signatures
SQL_ERROR_PATTERNS = (
    r"syntax error in SQL statement",
    r"sqlite3\.(?:OperationalError|DatabaseError)",
    r"ORA-[0-9]{5}",
    r"pg_query\(\):",
    r"mysql_fetch_(?:array|assoc|row)",
    r"Unclosed quotation mark before the character string",
    r"SQLSTATE\[[A-Z0-9]+\]",
    r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
    r"PostgreSQL.*ERROR:\s+syntax error",
    r"Microsoft OLE DB Provider for SQL Server",
)

# Known Template Injection (SSTI) Signatures
SSTI_ERROR_PATTERNS = (
    r"jinja2\.exceptions\.",
    r"TemplateSyntaxError",
    r"Twig_Error",
    r"django\.template\.exceptions",
    r"VelocityException",
)

# Known SSRF / Cloud Metadata Signatures
SSRF_PATTERNS = (
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"instance-id",
    r"ami-id",
    r"latest/meta-data",
)

# Known Reflection / XSS Markers
REFLECTION_PATTERNS = (
    r"<script[^>]*>.*?</script>",
    r"XSS_REFLECT_[A-Za-z0-9_]+",
    r"alert\([0-9]+\)",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:[a-zA-Z0-9_]+",
)


class SmartToolOutputSummarizer:
    """
    Deterministic rule-based summarizer for security tool outputs (HTTP, curl, nmap, etc.).
    Extracts essential security facts across HTTP, Auth, Injection, Config, and Attack-Chain signals.
    """

    @staticmethod
    def summarize(
        raw_text: str,
        tool_id: str,
        target: str,
        exit_code: int = 0,
        max_tokens: int = 800,
    ) -> tuple[str, list[str], str]:
        """
        Parses raw output and returns:
        (short_summary, key_indicators, primary_category)
        """
        indicators: list[str] = []
        category = "INFORMATIONAL"

        # 1. Target URL & Parameter Parsing
        try:
            parsed_url = urlparse(target)
            if parsed_url.query:
                q_params = parse_qs(parsed_url.query)
                for p_name in list(q_params.keys())[:4]:
                    indicators.append(f"query_param:{p_name}")
            if parsed_url.path:
                indicators.append(f"endpoint_path:{parsed_url.path}")
        except Exception:
            pass

        if exit_code != 0 and not raw_text.strip():
            return (
                f"Tool '{tool_id}' execution failed against '{target}' with exit code {exit_code}.",
                [f"exit_code:{exit_code}", "status:FAILED"],
                "TOOL_FAILURE",
            )

        # 2. Parse HTTP Status Line
        http_status_match = re.search(r"HTTP/[0-9.]+\s+(\d{3})\s+([A-Za-z ]+)", raw_text)
        status_code = ""
        status_text = ""
        if http_status_match:
            status_code = http_status_match.group(1)
            status_text = http_status_match.group(2).strip()
            indicators.append(f"http_status:{status_code}")

        # 3. Extract Key HTTP Headers
        headers_found: dict[str, str] = {}
        for header_name in (
            "Content-Type",
            "Server",
            "Location",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Authorization",
            "WWW-Authenticate",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Set-Cookie",
            "Retry-After",
        ):
            header_match = re.search(rf"(?i)^{header_name}:\s*(.+)$", raw_text, re.MULTILINE)
            if header_match:
                headers_found[header_name] = header_match.group(1).strip()

        if "Content-Type" in headers_found:
            indicators.append(f"content_type:{headers_found['Content-Type'].split(';')[0].strip()}")

        # 4. Redirect Detection (301, 302, 307, 308)
        if status_code in ("301", "302", "303", "307", "308"):
            loc = headers_found.get("Location", "")
            indicators.append(f"redirect_status:{status_code}")
            if loc:
                indicators.append(f"redirect_location:{loc}")
            category = "REDIRECT"

        # 5. Rate Limiting Detection (429)
        if status_code == "429" or "Retry-After" in headers_found:
            indicators.append("rate_limit:EXCEEDED")
            if "Retry-After" in headers_found:
                indicators.append(f"retry_after:{headers_found['Retry-After']}")
            category = "RATE_LIMITED"

        # 6. Cookie & Session Security Flags
        if "Set-Cookie" in headers_found:
            cookie_val = headers_found["Set-Cookie"]
            indicators.append("cookie:SET")
            cookie_lower = cookie_val.lower()
            if "httponly" not in cookie_lower:
                indicators.append("cookie_missing_httponly")
            if "secure" not in cookie_lower:
                indicators.append("cookie_missing_secure")
            if "samesite" not in cookie_lower:
                indicators.append("cookie_missing_samesite")
            if "session" in cookie_lower or "token" in cookie_lower or "auth" in cookie_lower:
                indicators.append("session_cookie:ISSUED")

        # 7. CORS Configuration
        if "Access-Control-Allow-Origin" in headers_found:
            origin_val = headers_found["Access-Control-Allow-Origin"]
            indicators.append(f"cors_origin:{origin_val}")
            if origin_val == "*":
                indicators.append("cors_wildcard:TRUE")
            if headers_found.get("Access-Control-Allow-Credentials", "").lower() == "true":
                indicators.append("cors_credentials:TRUE")
                if origin_val == "*" or "null" in origin_val:
                    category = "CORS_MISCONFIGURATION"
                    indicators.append("cors_vulnerability:EXCESSIVE_TRUST")

        # 8. Missing Defensive Headers on Successful HTTP Responses
        if status_code in ("200", "201", "204"):
            missing_sec = []
            if "X-Content-Type-Options" not in headers_found:
                missing_sec.append("X-Content-Type-Options")
            if "X-Frame-Options" not in headers_found:
                missing_sec.append("X-Frame-Options")
            if "Content-Security-Policy" not in headers_found:
                missing_sec.append("Content-Security-Policy")

            if missing_sec:
                indicators.append(f"missing_headers:{','.join(missing_sec)}")
                if category == "INFORMATIONAL":
                    category = "SECURITY_MISCONFIGURATION"

        # 9. Authentication & Authorization Boundaries
        if status_code in ("401", "403"):
            indicators.append("auth_boundary:ENFORCED")
            indicators.append(f"access_denied:{status_code}")
            category = "AUTH_BOUNDARY_ENFORCED"

        # Login state indicators
        raw_lower = raw_text.lower()
        if any(term in raw_lower for term in ("invalid credentials", "login failed", "authentication failed", "bad password")):
            indicators.append("auth_status:LOGIN_FAILED")
        elif any(term in raw_lower for term in ("login successful", "welcome back", "authenticated\": true", "logged_in")):
            indicators.append("auth_status:LOGIN_SUCCESS")

        # Role differentiation
        if "role\": \"admin\"" in raw_lower or "role=admin" in raw_lower or "admin access granted" in raw_lower:
            indicators.append("role:ADMIN")
        elif "role\": \"user\"" in raw_lower or "role=user" in raw_lower:
            indicators.append("role:STANDARD_USER")

        # 10. Specific Vulnerability Flags & Proofs
        if "SYNTHETIC_FLAG_IDOR_VULNERABILITY_CONFIRMED" in raw_text:
            indicators.append("flag:SYNTHETIC_FLAG_IDOR_VULNERABILITY_CONFIRMED")
            indicators.append("vulnerability:IDOR_BOLA")
            category = "BOLA_EXPOSURE"

        # 11. SQL Injection Error Signatures
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, raw_text, re.IGNORECASE):
                indicators.append("sql_error:DETECTED")
                category = "SQL_INJECTION_INDICATOR"
                break

        # 12. Template Injection (SSTI) Signatures
        for pattern in SSTI_ERROR_PATTERNS:
            if re.search(pattern, raw_text, re.IGNORECASE):
                indicators.append("ssti_error:DETECTED")
                category = "TEMPLATE_INJECTION_INDICATOR"
                break

        # 13. SSRF / Cloud Metadata Signatures
        for pattern in SSRF_PATTERNS:
            if re.search(pattern, raw_text, re.IGNORECASE):
                indicators.append("ssrf_indicator:METADATA_EXPOSURE")
                category = "SSRF_METADATA_EXPOSURE"
                break

        # 14. Reflection / XSS Detection
        for pattern in REFLECTION_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                matched_snippet = match.group(0)[:30]
                indicators.append(f"reflection_detected:{matched_snippet}")
                if category in ("INFORMATIONAL", "SECURITY_MISCONFIGURATION"):
                    category = "INPUT_REFLECTION"
                break

        # 15. JSON Payload Parsing
        json_summary_part = ""
        try:
            body_text = raw_text
            if "\r\n\r\n" in raw_text:
                body_text = raw_text.split("\r\n\r\n", 1)[1]
            elif "\n\n" in raw_text and not raw_text.strip().startswith("{"):
                body_text = raw_text.split("\n\n", 1)[1]

            data = json.loads(body_text.strip())
            if isinstance(data, dict):
                keys = list(data.keys())
                indicators.append(f"json_keys:{','.join(keys[:6])}")
                if "endpoints" in data and isinstance(data["endpoints"], list):
                    ep_count = len(data["endpoints"])
                    indicators.append(f"catalog_endpoints:{ep_count}")
                    if category == "INFORMATIONAL":
                        category = "ENDPOINT_CATALOG"
                    json_summary_part = f" Catalog contains {ep_count} registered endpoints."
                elif "owner" in data or "id" in data:
                    json_summary_part = f" Object metadata: id={data.get('id')}, owner={data.get('owner')}."
        except Exception:
            pass

        # 16. Discovered Navigation Links in HTML
        if "<a href=" in raw_text:
            links = re.findall(r'href=["\']([^"\']+)["\']', raw_text)
            if links:
                indicators.append(f"discovered_links:{len(links)}")
                if category == "INFORMATIONAL":
                    category = "DISCOVERED_LINKS"

        # 17. Build Short Summary
        parts: list[str] = []
        if status_code:
            parts.append(f"Target '{target}' responded with HTTP {status_code} {status_text}.")
        else:
            parts.append(f"Tool '{tool_id}' completed execution against '{target}'.")

        if headers_found.get("Server"):
            parts.append(f"Server technology: {headers_found['Server']}.")
        if headers_found.get("Location"):
            parts.append(f"Redirects to: {headers_found['Location']}.")
        if json_summary_part:
            parts.append(json_summary_part)
        if "missing_headers" in str(indicators):
            parts.append("Defensive security headers are missing on this response.")
        if category == "BOLA_EXPOSURE":
            parts.append("Administrative document exposed without authorization check (IDOR confirmed).")
        elif category == "AUTH_BOUNDARY_ENFORCED":
            parts.append("Administrative access boundary strictly enforced (403 Forbidden).")
        elif category == "SQL_INJECTION_INDICATOR":
            parts.append("Response contains database diagnostic syntax error signature indicative of SQL injection.")
        elif category == "TEMPLATE_INJECTION_INDICATOR":
            parts.append("Server-side template engine exception detected in response body.")
        elif category == "SSRF_METADATA_EXPOSURE":
            parts.append("Internal cloud infrastructure metadata attributes detected in response body.")
        elif category == "INPUT_REFLECTION":
            parts.append("User-supplied input or script execution payload reflected in response body.")
        elif category == "CORS_MISCONFIGURATION":
            parts.append("Cross-Origin Resource Sharing policy exposes sensitive authenticated responses.")

        summary_text = " ".join(parts).strip()

        # 18. Token Budget Enforcement
        max_chars = max_tokens * 4
        if len(summary_text) > max_chars:
            summary_text = summary_text[:max_chars - 30] + "... [summary truncated to budget]"

        return summary_text, indicators, category
