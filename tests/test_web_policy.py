"""Tests for the public-URL and CORS policy helpers."""

from __future__ import annotations

import pytest
from src.web_policy import extra_allowed_origins, is_local_host, same_origin_ok


def test_is_local_host_recognises_localhost():
    assert is_local_host("localhost") is True
    assert is_local_host("127.0.0.1") is True
    assert is_local_host("localhost:8000") is True
    assert is_local_host("LOCALHOST:3000") is True


def test_is_local_host_rejects_public_domains():
    assert is_local_host("codeguard.vercel.app") is False
    assert is_local_host("example.com") is False
    assert is_local_host("") is False
    assert is_local_host("notlocalhost.com") is False


def test_extra_origins_empty_when_unset(monkeypatch):
    monkeypatch.delenv("CODEGUARD_ALLOWED_ORIGINS", raising=False)
    assert extra_allowed_origins() == []


def test_extra_origins_parsed_and_normalised(monkeypatch):
    monkeypatch.setenv(
        "CODEGUARD_ALLOWED_ORIGINS",
        "https://a.example.com/, https://b.example.com",
    )
    assert extra_allowed_origins() == [
        "https://a.example.com",
        "https://b.example.com",
    ]


def test_extra_origins_drop_wildcards(monkeypatch):
    """A wildcard cannot be combined with credentialed CORS; never forward it."""
    monkeypatch.setenv("CODEGUARD_ALLOWED_ORIGINS", "*, https://ok.example.com")
    assert extra_allowed_origins() == ["https://ok.example.com"]


def test_extra_origins_drop_malformed(monkeypatch):
    monkeypatch.setenv(
        "CODEGUARD_ALLOWED_ORIGINS",
        "not-a-url, ftp://files.example.com, https://good.example.com",
    )
    assert extra_allowed_origins() == ["https://good.example.com"]


@pytest.mark.parametrize(
    "origin",
    ["https://codeguard.vercel.app", "http://localhost:8000", "https://a.b.c"],
)
def test_same_origin_ok_accepts_http_origins(origin):
    assert same_origin_ok(origin) is True


@pytest.mark.parametrize(
    "origin",
    ["", "javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "*"],
)
def test_same_origin_ok_rejects_non_http(origin):
    assert same_origin_ok(origin) is False
