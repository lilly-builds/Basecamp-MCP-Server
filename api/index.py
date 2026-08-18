"""
Vercel entry point for the Basecamp MCP server.

Three things are needed to run this MCP server on serverless.

1. No token file. Vercel has no writable disk, so BASECAMP_TOKEN_SOURCE=env makes
   token_storage fetch an access token using the refresh token from the
   environment and hold it in memory. Basecamp refresh tokens do not rotate, so
   this keeps itself alive without anyone pasting in a new token.

2. Startup once per instance. The MCP HTTP app starts its session manager in an
ASGI "lifespan" event that a normal server normally fires at boot. The Vercel
runtime can deliver that event separately from request handling, so we own the
session-manager lifespan in one dedicated, long-lived task instead. Otherwise
the manager's AnyIO task group can be entered by request one and used or exited
by request two, which is invalid. It must happen exactly once: the session
manager refuses a second .run() with "can only be called once per instance".

3. Host checking off. The MCP SDK ships DNS-rebinding protection that only
   allows localhost, which rejects a real domain with "421 Invalid Host header".
   That protection is aimed at servers bound to a developer's own machine; this
   one is reached over HTTPS on its own hostname.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('BASECAMP_TOKEN_SOURCE', 'env')

from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from basecamp_fastmcp import mcp  # noqa: E402

# All three must be set before the ASGI app is built.
mcp.settings.stateless_http = True
mcp.settings.json_response = True
mcp.settings.transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)

_inner = mcp.streamable_http_app()

_startup_lock = asyncio.Lock()
_ready = asyncio.Event()
_stop = asyncio.Event()
_startup_task = None
_startup_error = None


async def _run_lifespan():
    """Keep the MCP session manager alive in one task for this instance."""
    global _startup_error
    try:
        async with _inner.router.lifespan_context(_inner):
            _ready.set()
            await _stop.wait()
    except BaseException as exc:
        _startup_error = exc
        _ready.set()
        raise


async def _ensure_started():
    """Start the dedicated lifespan task exactly once and wait until ready."""
    global _startup_task
    if _startup_task is None:
        async with _startup_lock:
            if _startup_task is None:  # another request may have won the race
                _startup_task = asyncio.create_task(_run_lifespan())
    await _ready.wait()
    if _startup_error is not None:
        raise _startup_error


async def _handle_lifespan(receive, send):
    """Provide ASGI lifespan support without entering MCP's lifespan twice."""
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            try:
                await _ensure_started()
            except Exception as exc:
                await send({"type": "lifespan.startup.failed", "message": str(exc)})
                return
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            _stop.set()
            if _startup_task is not None:
                try:
                    await _startup_task
                except asyncio.CancelledError:
                    pass
            await send({"type": "lifespan.shutdown.complete"})
            return


async def app(scope, receive, send):
    """ASGI app that starts the MCP session manager once, then serves normally."""
    if scope["type"] == "lifespan":
        await _handle_lifespan(receive, send)
        return

    await _ensure_started()
    await _inner(scope, receive, send)
