import asyncio
import logging

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from app.core.validation import parse_run_request
from app.core.orchestrator import run_modules
from app.core.registry import all_modules, get_module

logger = logging.getLogger(__name__)
router = APIRouter()

_DONE = object()


def _parse_ids(modules: str | None) -> list[str] | None:
    if not modules:
        return None
    ids = [m.strip() for m in modules.split(",") if m.strip()]
    return ids or None


@router.get("/modules")
def list_modules():
    return [module.info() for module in all_modules()]


@router.get("/recon")
def recon_all(target: str, active: bool = False, modules: str | None = None):
    try:
        results = list(run_modules(target, _parse_ids(modules), allow_active=active))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "target": target,
        "active": active,
        "results": [r.model_dump() for r in results],
    }


@router.get("/recon/{module_id}")
def recon_one(module_id: str, target: str, active: bool = False):
    if get_module(module_id) is None:
        raise HTTPException(status_code=404, detail=f"Unknown module: {module_id}")
    try:
        results = list(run_modules(target, [module_id], allow_active=active))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return results[0].model_dump()


async def _send_error(websocket: WebSocket, message: str) -> None:
    try:
        await websocket.send_json({"stage": "error", "data": {"message": message}})
        await websocket.close()
    except Exception:
        pass


@router.websocket("/ws/recon")
async def recon_ws(websocket: WebSocket):
    await websocket.accept()
    iterator = None
    try:
        target, module_ids, active = parse_run_request(await websocket.receive_json())
        iterator = run_modules(target, module_ids, allow_active=active)

        count = 0
        while True:
            # The orchestrator blocks while it waits, so step it in a worker
            # thread and keep the event loop free to notice disconnects.
            result = await asyncio.to_thread(next, iterator, _DONE)
            if result is _DONE:
                break
            count += 1
            await websocket.send_json({"stage": "module", "data": result.model_dump()})

        await websocket.send_json({"stage": "done", "data": {"count": count}})
        await websocket.close()

    except WebSocketDisconnect:
        return
    except ValueError as exc:
        await _send_error(websocket, str(exc))
    except Exception:
        logger.exception("Recon websocket failed")
        await _send_error(websocket, "Internal error during recon")
    finally:
        if iterator is not None:
            try:
                iterator.close()
            except ValueError:
                pass  # generator was mid-step; the executor cleans itself up