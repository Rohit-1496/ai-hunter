# Hunter Schema Definitions — V1

**Version:** 1.0
**Status:** ACTIVE
**Note:** All schemas are versioned. Schema changes must be backward-compatible.

---

## Mission State Schema (v1)

File: `state/missions/<mission_id>/state.json`

```json
{
  "_schema": "mission_state_v1",
  "mission_id": "string — unique identifier e.g. M-001",
  "created_at": "ISO 8601 timestamp",
  "target_scope": ["string — allowed domains/IPs/ranges"],
  "excluded_scope": ["string — explicitly excluded"],
  "operator_objective": "string — plain text description of the mission goal",
  "risk_policy": "string — LOW | MEDIUM | HIGH",
  "time_budget_hours": "number | null",
  "resource_budget": {
    "max_requests_per_minute": "number | null",
    "max_concurrent_processes": "number | null"
  },
  "current_mode": "string — RECON | MAPPING | HYPOTHESIS | DEEP-DIVE | CHAINING | VALIDATION | REPORT | IDLE",
  "current_strategy": "string — brief description of current research strategy",
  "active_objectives": ["string"],
  "status": "string — ACTIVE | PAUSED | COMPLETED | ABORTED",
  "last_checkpoint": "ISO 8601 timestamp | null",
  "environment_fingerprint": "string | null",
  "target_fingerprint": "string | null"
}
```

---

## Event Log Entry Schema (v1)

File: `state/missions/<mission_id>/events.jsonl`
Format: Append-only JSONL, one JSON object per line.

```json
{
  "_schema": "event_v1",
  "event": "string — event type identifier",
  "mission": "string — mission_id",
  "timestamp": "ISO 8601 timestamp",
  "data": {}
}
```

### Event Types (Phase 1)

| Event | Description |
|-------|-------------|
| `runtime_started` | Hunter runtime initialized |
| `mission_created` | New mission was created |
| `mission_resumed` | Mission loaded from checkpoint |
| `checkpoint_saved` | Checkpoint persisted |
| `status_checked` | `hunter status` command executed |
| `handshake_sent` | `hi` command responded |

---

## Resume Capsule Schema (v1)

File: `state/missions/<mission_id>/resume_capsule.json`

```json
{
  "_schema": "resume_capsule_v1",
  "mission_id": "string",
  "capsule_created_at": "ISO 8601 timestamp",
  "scope_summary": "string — compact scope description",
  "strategy": "string — current strategy",
  "active_objectives": ["string"],
  "important_discoveries": ["string — compact references, not raw evidence"],
  "active_hypotheses": ["string — compact hypothesis summaries"],
  "relevant_negative_knowledge": ["string"],
  "highest_value_unknowns": ["string"],
  "current_attack_paths": ["string"],
  "recent_evidence_refs": ["string — file paths only"],
  "coverage_gaps": ["string"],
  "remaining_resources": {},
  "last_checkpoint": "ISO 8601 timestamp | null",
  "target_changes_detected": "boolean"
}
```

---

## Runtime Health Schema (v1)

Used by `hunter status` command.

```json
{
  "_schema": "runtime_health_v1",
  "timestamp": "ISO 8601 timestamp",
  "hunter": "ONLINE | OFFLINE",
  "adapter": "CONNECTED | DISCONNECTED",
  "subsystems": {
    "brain": "READY | UNAVAILABLE | ERROR",
    "memory": "READY | UNAVAILABLE | ERROR",
    "scope": "READY | UNAVAILABLE | ERROR",
    "executor": "READY | UNAVAILABLE | ERROR",
    "graph": "READY | UNAVAILABLE | ERROR",
    "checkpoints": "READY | UNAVAILABLE | ERROR"
  },
  "active_mission": "string | null",
  "error_details": {}
}
```

---

## Global Knowledge Entry Schema (v1)

File: `state/global/knowledge.jsonl`
Format: Append-only JSONL.

```json
{
  "_schema": "global_knowledge_v1",
  "knowledge_id": "string",
  "created_at": "ISO 8601 timestamp",
  "type": "string — METHODOLOGY | TOOL_RELIABILITY | HEURISTIC | LESSON",
  "title": "string",
  "description": "string",
  "confidence": "number 0.0-1.0",
  "source_missions": ["string — mission_id references"],
  "validated": "boolean",
  "tags": ["string"]
}
```

**IMPORTANT:** Global knowledge must never contain target-specific secrets, credentials, or PII.

---

## Hypothesis Schema (v1)

File: `state/missions/<mission_id>/hypotheses.jsonl`
Format: Append-only JSONL (state transitions append new entries).

```json
{
  "_schema": "hypothesis_v1",
  "hypothesis_id": "string — e.g. H-001",
  "statement": "string",
  "state": "string — NEW | ACTIVE | STRONG | VALIDATING | CONFIRMED | KILLED | DORMANT | REACTIVATED",
  "evidence_for": ["string — evidence refs"],
  "evidence_against": ["string — evidence refs"],
  "unknowns": ["string"],
  "confidence": "number 0.0-1.0",
  "next_experiment": "string | null",
  "created_at": "ISO 8601 timestamp",
  "updated_at": "ISO 8601 timestamp",
  "last_verified": "ISO 8601 timestamp | null"
}
```

**IMPORTANT:** Killed hypotheses are retained as negative knowledge. They are not deleted.
