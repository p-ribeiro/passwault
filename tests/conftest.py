"""Shared test configuration."""

import pytest


@pytest.fixture(autouse=True)
def _installed_mode_by_default(monkeypatch):
    """Keep a developer's PASSWAULT_HOME from switching tests into portable mode."""
    monkeypatch.delenv("PASSWAULT_HOME", raising=False)
