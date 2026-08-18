"""Regression tests for Vercel's no-lifespan HTTP execution path."""

import asyncio
import importlib

import httpx
import mcp.types


def _initialize_request():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": mcp.types.LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "vercel-regression-test", "version": "1.0"},
        },
    }


def test_streamable_http_handles_sequential_requests_without_asgi_lifespan():
    """Vercel can invoke requests without first forwarding a lifespan event."""
    import api.index

    server = importlib.reload(api.index)

    async def exercise_real_route():
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://basecamp-mcp.test",
            headers={"Accept": "application/json, text/event-stream"},
        ) as client:
            # Uvicorn gives each HTTP request a distinct task. Keep these
            # requests sequential but create separate tasks to reproduce the
            # Vercel execution model that caused the original failure.
            initialized = await asyncio.create_task(
                client.post("/mcp", json=_initialize_request())
            )
            first_list = await asyncio.create_task(
                client.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                )
            )
            second_list = await asyncio.create_task(
                client.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                )
            )

        assert initialized.status_code == 200
        assert initialized.json()["result"]["serverInfo"]["name"]
        assert first_list.status_code == 200
        assert len(first_list.json()["result"]["tools"]) == 82
        assert second_list.status_code == 200
        assert len(second_list.json()["result"]["tools"]) == 82

    asyncio.run(exercise_real_route())
