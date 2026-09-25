from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app, frontend_dist


def test_unknown_api_route_returns_json_404_not_spa_html() -> None:
    response = TestClient(app, base_url="http://localhost").get("/api/this-route-does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert "<!doctype html>" not in response.text.lower()


def test_browser_route_serves_spa_index_when_frontend_is_built() -> None:
    if not (frontend_dist / "index.html").is_file():
        return

    response = TestClient(app, base_url="http://localhost").get("/requests/new")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert Path(frontend_dist / "index.html").read_text(encoding="utf-8") in response.text
