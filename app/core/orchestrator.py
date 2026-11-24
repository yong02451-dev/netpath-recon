import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Iterator

import app.modules  # noqa: F401  (importing registers every module)
from app.core.base import ReconModule
from app.core.models import ModuleResult
from app.core.registry import all_modules, get_module
from app.core.validation import prepare_target


def _target_kind(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _select(module_ids: list[str] | None) -> list[ReconModule]:
    if module_ids is None:
        return all_modules()
    selected = []
    for module_id in dict.fromkeys(module_ids):  # drops duplicates, keeps order
        module = get_module(module_id)
        if module is None:
            raise ValueError(f"Unknown module: {module_id}")
        selected.append(module)
    return selected


def _skip_reason(module: ReconModule, kind: str, allow_active: bool) -> str | None:
    if module.tier == "active" and not allow_active:
        return "Active checks are off"
    if not module.has_key():
        return f"No API key configured (set {module.api_key_env})"
    if kind not in module.accepts:
        return "Does not accept IP addresses" if kind == "ip" else "Does not accept domain names"
    return None


def run_modules(
    raw_target: str,
    module_ids: list[str] | None = None,
    allow_active: bool = False,
    timeout: float = 120.0,
) -> Iterator[ModuleResult]:
    """
    Run modules against one target and yield each result as it is ready.
    Skipped modules come first (instantly), then the rest as they finish.
    Raises ValueError (on first iteration) for a bad target or unknown module.
    """
    modules = _select(module_ids)
    target = prepare_target(raw_target)
    kind = _target_kind(target)

    runnable = []
    for module in modules:
        reason = _skip_reason(module, kind, allow_active)
        if reason:
            yield module.skipped(reason)
        else:
            runnable.append(module)

    if not runnable:
        return

    executor = ThreadPoolExecutor(max_workers=min(8, len(runnable)))
    futures = {executor.submit(module.run, target): module for module in runnable}
    try:
        for future in as_completed(futures, timeout=timeout):
            yield future.result()   # run() never raises, so this is safe
    except FutureTimeout:
        for future, module in futures.items():
            if not future.done():
                yield ModuleResult(
                    module=module.id, name=module.name, tier=module.tier,
                    status="error", source=module.source,
                    error=f"Timed out after {timeout:.0f}s",
                )
    finally:
        # Also runs if the caller stops early (e.g. the browser disconnects)
        executor.shutdown(wait=False, cancel_futures=True)