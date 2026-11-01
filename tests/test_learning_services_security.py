import asyncio
import importlib

import httpx
import pytest


def _request(app, origin):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.options(
                "/",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )

    return asyncio.run(run())


@pytest.fixture(
    params=["services.learning_service.main", "api.main"],
    ids=["learning-service", "self-learning-agent"],
)
def service_app(request):
    try:
        module = importlib.import_module(request.param)
    except ModuleNotFoundError as exc:
        pytest.skip(f"Optional learning-service dependency is unavailable: {exc.name}")
    return module.app


def test_learning_apis_allow_local_browser_origins_without_credentials(service_app):
    response = _request(service_app, "http://localhost:3000")

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-credentials" not in response.headers
    assert "POST" in response.headers["access-control-allow-methods"]


def test_learning_apis_reject_nonlocal_browser_origins(service_app):
    response = _request(service_app, "https://attacker.invalid")

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
