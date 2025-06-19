import pytest


@pytest.fixture
def safe_test_target():
    """Safe test target URL for integration tests."""
    return "http://httpbin.org"


@pytest.fixture
def invalid_test_target():
    """Invalid target for error handling tests."""
    return "invalid-url-test-12345"


# Pytest markers for better test organization
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
