import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.validation import parse_run_request
from app.pipeline import run_trace, run_trace_stream

logger = logging.getLogger(__name__)
router = APIRouter()

_DONE = object()


@router.get("/trace")
def trace_endpoint(target: str, active: bool = False):
    # run_trace validates internally; problems appear under the "error" key
    return run_trace(target, allow_active=active)


async def _send_error(websocket: WebSocket, message: str) -> None:
    try:
        await websocket.send_json({"stage": "error", "data": {"message": message}})
        await websocket.close()
    except Exception:
        pass


@router.websocket("/ws/trace")
async def trace_ws(websocket: WebSocket):
    await websocket.accept()
    iterator = None
    try:
        target, module_ids, active = parse_run_request(await websocket.receive_json())
        iterator = run_trace_stream(target, module_ids=module_ids, allow_active=active)

        while True:
            # The pipeline blocks while it works, so step it in a worker thread
            # and keep the event loop free to notice a disconnect.
            event = await asyncio.to_thread(next, iterator, _DONE)
            if event is _DONE:
                break
            await websocket.send_json(event)

        await websocket.close()

    except WebSocketDisconnect:
        return
    except ValueError as exc:
        await _send_error(websocket, str(exc))
    except Exception:
        logger.exception("Trace websocket failed")
        await _send_error(websocket, "Internal error during trace")
    finally:
        if iterator is not None:
            try:
                iterator.close()
            except ValueError:
                pass  # generator was mid-step; nothing more to clean up here