"""Fail-closed included-only billing policy for a future worker adapter."""
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
from queue import Empty, Queue
import re
import subprocess
import threading
import time
from typing import Callable, TypeVar

_Result = TypeVar("_Result")
INCLUDED_ONLY = "INCLUDED_ONLY"
PLAN_TYPES = frozenset({
    "free", "go", "plus", "pro", "prolite", "promax", "team",
    "self_serve_business_prolite", "self_serve_business_usage_based",
    "business", "ent26", "enterprise_cbp_automation", "enterprise_cbp_usage_based",
    "enterprise", "edu", "edu_plus", "edu_pro", "sci", "sci_plus", "unknown",
})


def account_fingerprint(account_id: str, comparison_key: bytes) -> str:
    if not account_id.strip() or len(comparison_key) < 32:
        raise ValueError("A nonempty account identity and at least 32 comparison bytes are required.")
    return hmac.new(comparison_key, account_id.strip().casefold().encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AccountObservation:
    authentication: str
    account_fingerprint: str | None
    workspace_identity: str | None
    ordinary_usage_allowed: bool | None
    remaining_included_percent: float | None
    has_credits: bool | None
    auto_reload_enabled: bool | None
    observed_at: float


@dataclass(frozen=True)
class IncludedOnlyPolicy:
    account_fingerprint: str
    workspace_identity: str
    mode: str = INCLUDED_ONLY


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str


class WorkerAccountBlocked(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def evaluate_included_only(policy: IncludedOnlyPolicy, observed: AccountObservation, *, now: float) -> Decision:
    if policy.mode != INCLUDED_ONLY:
        return Decision(False, "PAID_FALLBACK_DISABLED")
    if observed.authentication != "chatgpt":
        return Decision(False, "SUBSCRIPTION_AUTH_REQUIRED")
    if not observed.account_fingerprint or not observed.workspace_identity:
        return Decision(False, "ACCOUNT_USAGE_UNVERIFIED")
    if (observed.account_fingerprint != policy.account_fingerprint
            or observed.workspace_identity != policy.workspace_identity):
        return Decision(False, "WORKER_ACCOUNT_CHANGED")
    if not math.isfinite(observed.observed_at) or not math.isfinite(now) or not 0 <= now - observed.observed_at <= 30:
        return Decision(False, "ACCOUNT_USAGE_UNVERIFIED")
    if observed.ordinary_usage_allowed is False or observed.remaining_included_percent == 0:
        return Decision(False, "QUOTA_EXHAUSTED")
    remaining = observed.remaining_included_percent
    if (observed.has_credits is not False or observed.auto_reload_enabled is not False
            or observed.ordinary_usage_allowed is not True or remaining is None or not 0 < remaining <= 100):
        return Decision(False, "ACCOUNT_USAGE_UNVERIFIED")
    return Decision(True, "INCLUDED_USAGE_OBSERVED")


def start_if_included(policy: IncludedOnlyPolicy, observe: Callable[[], AccountObservation],
                      launch: Callable[[], _Result], *, now: float) -> _Result:
    decision = evaluate_included_only(policy, observe(), now=now)
    if not decision.allowed:
        raise WorkerAccountBlocked(decision.code)
    return launch()


def summarize_account(account: dict, limits: dict, models: dict) -> dict:
    identity = account.get("account") or {}
    rate = limits.get("rateLimits") or {}
    credits = rate.get("credits") or {}

    def answer(container, key):
        value = container.get(key)
        return value if type(value) is bool else None

    visible = []
    for model in models.get("data", []):
        name = model.get("model") or model.get("id")
        if not model.get("hidden") and isinstance(name, str) and re.fullmatch(r"gpt-[a-z0-9.-]{1,80}", name):
            visible.append(name)
    plan = identity.get("planType")
    plan = plan if plan in PLAN_TYPES else None
    ordinary = answer(limits, "ordinaryUsageAllowed")
    if ordinary is None:
        ordinary = answer(rate, "ordinaryUsageAllowed")
    reached = answer(limits, "spendControlReached")
    if reached is None:
        reached = answer(rate, "spendControlReached")

    def num_field(container, key):
        if not isinstance(container, dict):
            return None
        val = container.get(key)
        return val if isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val) else None

    reached_type = limits.get("rateLimitReachedType") or rate.get("rateLimitReachedType")
    if not isinstance(reached_type, str) or "@" in reached_type or len(reached_type) > 64:
        reached_type = None
    primary = rate.get("primary") or {}
    secondary = rate.get("secondary") or {}
    indiv = limits.get("individualLimit") or rate.get("individualLimit") or {}
    return {
        "authentication": "chatgpt" if identity.get("type") == "chatgpt" else "unverified",
        "plan": plan,
        "has_credits": answer(credits, "hasCredits"),
        "unlimited_credits": answer(credits, "unlimited"),
        "ordinary_usage_allowed": ordinary,
        "spend_control_reached": reached,
        "rate_limit_reached_type": reached_type,
        "primary_used_percent": num_field(primary, "usedPercent"),
        "secondary_used_percent": num_field(secondary, "usedPercent"),
        "individual_used_percent": num_field(indiv, "usedPercent"),
        "has_account_id": bool(identity.get("accountId")),
        "has_workspace_name": bool(identity.get("workspaceName")),
        "auto_reload_verified": False,
        "models": sorted(set(visible)),
        "worker_policy": INCLUDED_ONLY,
        "workers_enabled": False,
    }


def probe_provider_account() -> dict:
    """Perform a fixed metadata-only exchange with the supported Codex app server."""
    from .runner import CODEX_SHA256, _codex_path

    codex = _codex_path()
    try:
        with codex.open("rb") as binary:
            if hashlib.file_digest(binary, "sha256").hexdigest() != CODEX_SHA256:
                raise WorkerAccountBlocked("PROVIDER_TOOLCHAIN_UNVERIFIED")
        server = subprocess.Popen(
            [str(codex), "app-server", "--listen", "stdio://"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError as error:
        raise WorkerAccountBlocked("PROVIDER_PROBE_UNAVAILABLE") from error
    received = Queue(maxsize=12)

    def read_replies():
        while len(line := server.stdout.readline(1_048_577)) <= 1_048_576 and line:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and isinstance(item.get("id"), int) and ("result" in item or "error" in item):
                received.put(item)
        received.put(None)

    def exchange(method, identity=None, payload=None):
        message = {"method": method}
        if identity is not None:
            message["id"] = identity
        if payload is not None:
            message["params"] = payload
        server.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        server.stdin.flush()
        if identity is None:
            return None
        limit = time.monotonic() + 10
        while True:
            item = received.get(timeout=max(0, limit - time.monotonic()))
            if item is None or time.monotonic() > limit:
                raise WorkerAccountBlocked("PROVIDER_PROBE_UNAVAILABLE")
            if item["id"] == identity:
                if not isinstance(item.get("result"), dict):
                    raise WorkerAccountBlocked("PROVIDER_METADATA_NOT_SUPPORTED")
                return item["result"]

    thread = threading.Thread(target=read_replies, daemon=True)
    thread.start()
    try:
        exchange("initialize", 1, {"clientInfo": {"name": "edge_bridge_diagnostics",
                                                   "title": "Edge Bridge Diagnostics", "version": "0.1.0"}})
        exchange("initialized")
        account = exchange("account/read", 2, {"refreshToken": False})
        limits = exchange("account/rateLimits/read", 3, {})
        models = exchange("model/list", 4, {"includeHidden": False, "limit": 50})
        return summarize_account(account, limits, models)
    except (Empty, OSError, TypeError, AttributeError, ValueError) as error:
        raise WorkerAccountBlocked("PROVIDER_PROBE_UNAVAILABLE") from error
    finally:
        server.stdin.close()
        try:
            server.wait(5)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(5)
        thread.join(1)
        server.stdout.close()

