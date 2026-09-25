from fastapi import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_TOO_LARGE = {"detail": "Request body too large"}


class BodySizeLimitMiddleware:
    """Rejects oversized request bodies before they are buffered in memory.

    FastAPI reads the whole body before validating it, so a size limit must come first.
    Two cases: a declared Content-Length (rejected immediately), and a chunked body with no
    declared length (counted as it streams in, and aborted once over the limit).
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await JSONResponse(_TOO_LARGE, status_code=413)(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI's body parsing re-raises HTTPException untouched (any other
                    # exception would be turned into a 400).
                    raise HTTPException(status_code=413, detail=_TOO_LARGE["detail"])
            return message

        await self.app(scope, limited_receive, send)
