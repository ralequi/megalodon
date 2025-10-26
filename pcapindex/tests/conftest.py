import pytest
from django.test import AsyncClient


@pytest.fixture(autouse=True)
def allow_async_db(monkeypatch):
    """Permit synchronous ORM usage inside async test contexts."""

    monkeypatch.setenv("DJANGO_ALLOW_ASYNC_UNSAFE", "true")


@pytest.fixture
def async_client():
    """Return a Django async test client."""

    return AsyncClient()
