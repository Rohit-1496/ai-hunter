"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Discovery Normalization Layer
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any


class EndpointNormalizer:
    """
    Normalizes endpoints, URLs, and paths to prevent duplicate representations
    while preserving security-relevant distinctions.
    """

    @staticmethod
    def normalize_url(raw_url: str, base_url: str | None = None) -> str:
        """
        Normalizes a URL string against a base URL.
        - Resolves relative URLs.
        - Strips URL fragments (#...).
        - Lowercases scheme and hostname.
        - Removes default ports (80 for http, 443 for https).
        - Collapses duplicate path slashes.
        - Normalizes query parameters (sorted).
        """
        if not raw_url:
            return ""

        raw_url = raw_url.strip()

        # Handle scheme-relative URLs
        if raw_url.startswith("//"):
            raw_url = f"http:{raw_url}"

        # If relative URL and base_url is provided, join with base
        if base_url and not (raw_url.startswith("http://") or raw_url.startswith("https://")):
            raw_url = urllib.parse.urljoin(base_url, raw_url)

        try:
            parsed = urllib.parse.urlparse(raw_url)
        except Exception:
            return raw_url

        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()

        # Strip default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Path normalization: collapse multiple slashes, resolve . and ..
        path = parsed.path or "/"
        # Replace multiple consecutive slashes with single slash
        path = re.sub(r"/+", "/", path)

        # Canonical path resolution
        segments = []
        for seg in path.split("/"):
            if seg == "." or seg == "":
                continue
            elif seg == "..":
                if segments:
                    segments.pop()
            else:
                segments.append(seg)
        normalized_path = "/" + "/".join(segments)
        # Preserve root slash
        if not normalized_path:
            normalized_path = "/"

        # Sort query parameters canonically
        query = ""
        if parsed.query:
            params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            sorted_params = sorted(params, key=lambda x: (x[0], x[1]))
            query = urllib.parse.urlencode(sorted_params)

        if not netloc:
            # Relative path only
            result = normalized_path
            if query:
                result = f"{result}?{query}"
            return result

        result = urllib.parse.urlunparse((scheme, netloc, normalized_path, "", query, ""))
        return result

    @staticmethod
    def extract_parameters(url: str, form_data: dict[str, Any] | None = None, json_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """
        Extracts all query, path, form, and JSON parameters from input sources.
        """
        parameters = []
        parsed = urllib.parse.urlparse(url)

        # Query parameters
        if parsed.query:
            for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                parameters.append({
                    "name": k,
                    "type": "QUERY",
                    "sample_value": v,
                    "location": "URL_QUERY"
                })

        # Path parameters detection (e.g. /api/users/123 or /api/items/{id})
        path_segments = [s for s in parsed.path.split("/") if s]
        for idx, segment in enumerate(path_segments):
            if segment.isdigit():
                parameters.append({
                    "name": f"path_param_{idx}",
                    "type": "PATH_NUMERIC",
                    "sample_value": segment,
                    "location": f"PATH_SEGMENT_{idx}"
                })
            elif re.match(r"^[0-9a-fA-F\-]{36}$", segment):  # UUID
                parameters.append({
                    "name": f"path_uuid_{idx}",
                    "type": "PATH_UUID",
                    "sample_value": segment,
                    "location": f"PATH_SEGMENT_{idx}"
                })

        # Form fields
        if form_data:
            for k, v in form_data.items():
                parameters.append({
                    "name": k,
                    "type": "FORM_BODY",
                    "sample_value": str(v),
                    "location": "FORM_DATA"
                })

        # JSON fields
        if json_data and isinstance(json_data, dict):
            for k, v in json_data.items():
                parameters.append({
                    "name": k,
                    "type": "JSON_BODY",
                    "sample_value": str(v),
                    "location": "JSON_PAYLOAD"
                })

        return parameters


class AssetNormalizer:
    """
    Normalizes domain names, subdomains, and hostnames.
    """

    @staticmethod
    def normalize_hostname(hostname: str) -> str:
        if not hostname:
            return ""
        h = hostname.strip().lower()
        if h.endswith("."):
            h = h[:-1]
        return h
