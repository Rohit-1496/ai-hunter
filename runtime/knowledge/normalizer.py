"""
Phase 13: Knowledge Normalizer

Standardizes vulnerability classes, technology identifiers, endpoint patterns,
and authorization taxonomy into canonical representations.
"""

from __future__ import annotations

import re
from runtime.knowledge.models import SecurityKnowledge


class KnowledgeNormalizer:
    """Normalizes terminology, taxonomy, and route templates across knowledge items."""

    # Canonical vulnerability mapping
    VULNERABILITY_TAXONOMY: dict[str, str] = {
        "IDOR": "OBJECT_LEVEL_AUTHORIZATION_FAILURE",
        "BOLA": "OBJECT_LEVEL_AUTHORIZATION_FAILURE",
        "INSECURE_DIRECT_OBJECT_REFERENCE": "OBJECT_LEVEL_AUTHORIZATION_FAILURE",
        "BROKEN_OBJECT_LEVEL_AUTHORIZATION": "OBJECT_LEVEL_AUTHORIZATION_FAILURE",
        "BFLA": "FUNCTION_LEVEL_AUTHORIZATION_FAILURE",
        "BROKEN_FUNCTION_LEVEL_AUTHORIZATION": "FUNCTION_LEVEL_AUTHORIZATION_FAILURE",
        "BAC": "BROKEN_ACCESS_CONTROL",
        "ACCESS_CONTROL_BYPASS": "BROKEN_ACCESS_CONTROL",
        "SSRF": "SERVER_SIDE_REQUEST_FORGERY",
        "SQLI": "SQL_INJECTION",
        "XSS": "CROSS_SITE_SCRIPTING",
        "CORS_MISCONFIG": "CROSS_ORIGIN_RESOURCE_SHARING_MISCONFIGURATION",
        "TENANT_ISOLATION_FAILURE": "MULTI_TENANT_DATA_LEAKAGE",
        "TENANT_LEAK": "MULTI_TENANT_DATA_LEAKAGE",
        "SESSION_FIXATION": "SESSION_MANAGEMENT_FAILURE",
        "AUTH_BYPASS": "AUTHENTICATION_BYPASS",
    }

    # Canonical technology mapping
    TECH_TAXONOMY: dict[str, str] = {
        "fastapi": "FastAPI",
        "flask": "Flask",
        "django": "Django",
        "express": "Express.js",
        "spring": "Spring Boot",
        "springboot": "Spring Boot",
        "rails": "Ruby on Rails",
        "laravel": "Laravel",
        "nextjs": "Next.js",
        "react": "React",
        "graphql": "GraphQL",
        "grpc": "gRPC",
        "jwt": "JWT",
        "oauth": "OAuth2",
        "oauth2": "OAuth2",
        "postgres": "PostgreSQL",
        "postgresql": "PostgreSQL",
        "mysql": "MySQL",
        "redis": "Redis",
        "mongodb": "MongoDB",
    }

    def normalize_vulnerability_class(self, vclass: str) -> str:
        """Maps synonymous vulnerability names to standard canonical taxonomy."""
        if not vclass:
            return "UNKNOWN"
        cleaned = vclass.strip().upper().replace(" ", "_").replace("-", "_")
        return self.VULNERABILITY_TAXONOMY.get(cleaned, cleaned)

    def normalize_technology(self, tech_name: str) -> str:
        """Normalizes technology name to canonical casing/naming."""
        if not tech_name:
            return ""
        cleaned = tech_name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
        return self.TECH_TAXONOMY.get(cleaned, tech_name.strip())

    def normalize_endpoint_pattern(self, pattern: str) -> str:
        """Replaces variable IDs and tokens with standard placeholders."""
        if not pattern:
            return "/"
        clean = pattern.strip()
        # Normalize UUIDs
        clean = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '{id}', clean)
        # Normalize numeric IDs
        clean = re.sub(r'/\d+(?=/|$)', '/{id}', clean)
        # Normalize hex hashes
        clean = re.sub(r'/[a-fA-F0-9]{16,}(?=/|$)', '/{token}', clean)
        return clean

    def normalize_knowledge(self, knowledge: SecurityKnowledge) -> SecurityKnowledge:
        """Normalizes an entire SecurityKnowledge instance in place."""
        knowledge.normalized_pattern = self.normalize_endpoint_pattern(knowledge.normalized_pattern)
        knowledge.applicable_technology = [self.normalize_technology(t) for t in knowledge.applicable_technology]
        knowledge.applicable_endpoint_types = [self.normalize_endpoint_pattern(ep) for ep in knowledge.applicable_endpoint_types]
        
        # Deduplicate list attributes after normalization
        knowledge.applicable_technology = sorted(list(set(filter(None, knowledge.applicable_technology))))
        knowledge.applicable_endpoint_types = sorted(list(set(filter(None, knowledge.applicable_endpoint_types))))
        
        knowledge.compute_digest()
        return knowledge
