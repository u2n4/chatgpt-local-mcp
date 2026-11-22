"""Model-agnostic dynamic capability detection and local Codex/CLI fallback planning."""

from __future__ import annotations

import json
import re
from typing import Any

PREFERRED_DEFAULT_MODEL = "GPT-6 Pro"
REFERENCE_MODELS = ("GPT-6 Pro", "Extra High", "High", "Medium")
CANONICAL_CAPABILITIES = (
    "mcp_invoke",
    "mcp_read",
    "mcp_write",
    "file_write",
    "command_exec",
    "subagents",
    "windows_control",
)
_CAPABILITY_SET = frozenset(CANONICAL_CAPABILITIES)
EDGE_FORBIDDEN_CAPABILITIES = frozenset({"mcp_write", "file_write", "command_exec", "windows_control"})
ACTION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "inspect_project": ("mcp_invoke", "mcp_read"),
    "patch_apply": ("mcp_write", "file_write"),
    "run_tests": ("command_exec",),
    "git_mutate": ("command_exec", "file_write"),
    "spawn_workers": ("subagents",),
    "desktop_control": ("windows_control",),
}

_SURFACE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}\Z")
_SAFE_OP_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")


def normalize_model_id(model_id: str) -> str:
    """Validate syntax of any compatible model label without any hardcoded allowlist/blocklist."""
    if not isinstance(model_id, str):
        raise ValueError("model_id must be a string.")
    cleaned = model_id.strip()
    if not 1 <= len(cleaned) <= 128:
        raise ValueError("model_id must be between 1 and 128 characters.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise ValueError("model_id cannot contain control characters.")
    return cleaned


def validate_surface(surface: str) -> str:
    if not isinstance(surface, str) or not _SURFACE_RE.fullmatch(surface):
        raise ValueError("surface must match [a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}.")
    return surface


def validate_capability_map(capabilities: dict[str, Any]) -> dict[str, bool]:
    if not isinstance(capabilities, dict) or not capabilities:
        raise ValueError("capabilities must be a non-empty JSON object.")
    validated: dict[str, bool] = {}
    for key, val in capabilities.items():
        if key not in _CAPABILITY_SET:
            raise ValueError(f"Unsupported capability key: {key!r}")
        if type(val) is not bool:
            raise ValueError(f"Capability {key!r} must be a boolean.")
        validated[key] = val
    return {k: validated[k] for k in CANONICAL_CAPABILITIES if k in validated}


def effective_capabilities(
    observed: dict[str, bool] | None,
    *,
    principal: str,
    surface: str | None = None,
) -> dict[str, bool | None]:
    """Compute effective capabilities; unobserved stays None and edge read-only caps stay False."""
    result: dict[str, bool | None] = {cap: None for cap in CANONICAL_CAPABILITIES}
    if observed:
        for cap in CANONICAL_CAPABILITIES:
            if cap in observed and type(observed[cap]) is bool:
                result[cap] = observed[cap]
    edge_restricted = principal == "edge" or (surface is not None and "edge" in surface.casefold())
    if edge_restricted:
        for cap in EDGE_FORBIDDEN_CAPABILITIES:
            result[cap] = False
    return result


def aggregate_capabilities(
    observations: list[dict[str, Any]],
    *,
    principal: str,
) -> dict[str, Any]:
    """Deterministically aggregate persisted (model_id, surface) observations."""
    ordered = sorted(
        observations,
        key=lambda item: (str(item.get("model_id", "")), str(item.get("surface", ""))),
    )
    by_model: dict[str, dict[str, Any]] = {}
    entries: list[dict[str, Any]] = []
    for item in ordered:
        model_id = str(item["model_id"])
        surface = str(item["surface"])
        raw_caps = dict(item.get("capabilities") or {})
        eff = effective_capabilities(raw_caps, principal=principal, surface=surface)
        entry = {
            "model_id": model_id,
            "surface": surface,
            "observed_capabilities": {k: raw_caps[k] for k in CANONICAL_CAPABILITIES if k in raw_caps},
            "effective_capabilities": eff,
            "source": item.get("source", ""),
            "notes": item.get("notes", ""),
            "observed_at": item.get("observed_at", ""),
            "policy_enforced": principal == "edge" or "edge" in surface.casefold(),
        }
        entries.append(entry)
        model_bucket = by_model.setdefault(
            model_id,
            {
                "model_id": model_id,
                "surfaces": {},
                "effective_capabilities": {cap: None for cap in CANONICAL_CAPABILITIES},
            },
        )
        model_bucket["surfaces"][surface] = entry

    for model_bucket in by_model.values():
        surface_entries = list(model_bucket["surfaces"].values())
        for cap in CANONICAL_CAPABILITIES:
            if principal == "edge" and cap in EDGE_FORBIDDEN_CAPABILITIES:
                model_bucket["effective_capabilities"][cap] = False
                continue
            vals = [s_entry["effective_capabilities"].get(cap) for s_entry in surface_entries]
            if any(v is True for v in vals):
                model_bucket["effective_capabilities"][cap] = True
            elif any(v is False for v in vals):
                model_bucket["effective_capabilities"][cap] = False
            else:
                model_bucket["effective_capabilities"][cap] = None

    return {
        "model_agnostic": True,
        "allowlist_enforced": False,
        "preferred_default_model": PREFERRED_DEFAULT_MODEL,
        "reference_models": list(REFERENCE_MODELS),
        "canonical_capabilities": list(CANONICAL_CAPABILITIES),
        "observations": entries,
        "by_model": [by_model[key] for key in sorted(by_model)],
    }


def summarize_for_info(
    observations: list[dict[str, Any]],
    *,
    principal: str,
    codex_present: bool,
) -> dict[str, Any]:
    aggregated = aggregate_capabilities(observations, principal=principal)
    return {
        "model_agnostic": True,
        "allowlist_enforced": False,
        "preferred_default_model": PREFERRED_DEFAULT_MODEL,
        "reference_models": list(REFERENCE_MODELS),
        "canonical_capabilities": list(CANONICAL_CAPABILITIES),
        "observed_models": [item["model_id"] for item in aggregated["by_model"]],
        "observation_count": len(aggregated["observations"]),
        "observations": aggregated["observations"],
        "local_codex_available": bool(codex_present),
        "note": "Unobserved capabilities remain null/unknown until dynamically observed; edge principal enforces read-only.",
    }


def _select_observation(
    observations: list[dict[str, Any]],
    *,
    model_id: str | None,
    surface: str | None,
) -> tuple[str, str, dict[str, bool]]:
    target_model = normalize_model_id(model_id) if model_id is not None else PREFERRED_DEFAULT_MODEL
    ordered = sorted(
        observations,
        key=lambda item: (str(item.get("model_id", "")), str(item.get("surface", ""))),
    )
    if surface is not None:
        validate_surface(surface)
        for item in ordered:
            if item.get("model_id") == target_model and item.get("surface") == surface:
                return target_model, surface, dict(item.get("capabilities") or {})
        return target_model, surface, {}
    for item in ordered:
        if item.get("model_id") == target_model:
            return target_model, str(item.get("surface") or "chatgpt_web_edge"), dict(item.get("capabilities") or {})
    default_surface = "chatgpt_web_edge"
    return target_model, default_surface, {}


def build_fallback_plan(
    *,
    project_id: str,
    task_id: str | None,
    operation_id: str,
    principal: str,
    required_capabilities: list[str] | tuple[str, ...],
    observations: list[dict[str, Any]],
    model_id: str | None = None,
    surface: str | None = None,
    state_dir_hint: str | None = None,
    project_root_hint: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic authorized local Codex/CLI fallback plan when capabilities are missing."""
    if not isinstance(operation_id, str) or not _SAFE_OP_RE.fullmatch(operation_id):
        raise ValueError("Invalid operation_id for fallback plan.")
    if task_id is not None and (not isinstance(task_id, str) or not _SAFE_OP_RE.fullmatch(task_id)):
        raise ValueError("Invalid task_id for fallback plan.")
    if not required_capabilities:
        raise ValueError("required_capabilities must be non-empty.")
    req_list: list[str] = []
    for cap in required_capabilities:
        if cap not in _CAPABILITY_SET:
            raise ValueError(f"Unsupported required capability: {cap!r}")
        if cap not in req_list:
            req_list.append(cap)

    default_surface = surface or ("chatgpt_web_edge" if principal == "edge" else "local_codex_cli")
    target_model, matched_surface, raw_caps = _select_observation(
        observations, model_id=model_id, surface=default_surface,
    )
    eff = effective_capabilities(raw_caps, principal=principal, surface=matched_surface)
    missing = [cap for cap in req_list if eff.get(cap) is not True]
    fallback_required = len(missing) > 0

    if principal == "edge":
        safe_state_dir = r"%LOCALAPPDATA%\EdgeProjectBridge"
        safe_root = "<approved_project_root>"
    else:
        safe_state_dir = state_dir_hint or r"%LOCALAPPDATA%\EdgeProjectBridge"
        safe_root = project_root_hint or "<approved_project_root>"

    edge_blocked = [cap for cap in missing if cap in EDGE_FORBIDDEN_CAPABILITIES]
    if principal == "edge" and edge_blocked:
        reason = "EDGE_PRINCIPAL_READ_ONLY"
    elif any(eff.get(cap) is False for cap in missing):
        reason = "MODEL_CAPABILITY_UNAVAILABLE"
    else:
        reason = "MODEL_CAPABILITY_UNOBSERVED"

    task_label = task_id or "active-task"
    commands: list[dict[str, str]] = []
    if fallback_required:
        if "file_write" in missing or "mcp_write" in missing:
            commands.append({
                "action": "apply_patch_plan",
                "executor": "edge_bridge.cli",
                "command": (
                    f"uv run --locked --no-sync python -m edge_bridge.cli "
                    f"--state-dir {safe_state_dir} apply-patch-plan {project_id} "
                    f"--operation-id {operation_id} --task-id {task_label} --json <patch.json> --confirm --verify"
                ),
            })
        if "command_exec" in missing:
            exec_op = f"{operation_id[:123]}-exec" if len(operation_id) > 123 else f"{operation_id}-exec"
            process_payload = json.dumps(
                {
                    "project_id": project_id,
                    "task_id": task_label,
                    "operation_id": exec_op,
                    "executable": "python",
                    "argv": ["-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                },
                separators=(",", ":"),
            )
            commands.append({
                "action": "run_local_tests",
                "executor": "edge_bridge.cli",
                "command": (
                    f"uv run --locked --no-sync python -m edge_bridge.cli "
                    f"--state-dir {safe_state_dir} call process_start --json "
                    f"'{process_payload}'"
                ),
            })
        commands.append({
            "action": "run_local_codex",
            "executor": "codex",
            "command": (
                f"codex exec --cd {safe_root} "
                f"\"Resume project {project_id} task {task_label} (operation_id={operation_id}) "
                f"using edge_bridge.cli against {safe_state_dir}.\""
            ),
        })

    return {
        "fallback_required": fallback_required,
        "task_preserved": True,
        "project_id": project_id,
        "task_id": task_id,
        "operation_id": operation_id,
        "principal": principal,
        "model_id": target_model,
        "surface": matched_surface,
        "reason": reason if fallback_required else "CAPABILITIES_SATISFIED",
        "required_capabilities": req_list,
        "missing_capabilities": missing,
        "effective_capabilities": eff,
        "requires_local_owner_authorization": True,
        "commands": commands,
    }
