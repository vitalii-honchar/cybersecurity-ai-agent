import threading
import time

import pytest
import requests
import uvicorn

from src.api_target.main import app


@pytest.fixture(scope="session")
def fastapi_server():
    """Start FastAPI server for testing - available for all target_scan_agent tests."""
    server_thread = None
    server_port = 8080
    server_url = f"http://localhost:{server_port}"

    # Start server in background thread
    config = uvicorn.Config(
        app, host="127.0.0.1", port=server_port, log_level="warning"
    )
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to be ready
    max_retries = 30
    for _ in range(max_retries):
        try:
            response = requests.get(f"{server_url}/health", timeout=1)
            if response.status_code == 200:
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    else:
        pytest.fail("FastAPI server failed to start")

    yield server_url

    # Cleanup is automatic since thread is daemon
