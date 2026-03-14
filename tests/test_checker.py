from unittest.mock import AsyncMock, MagicMock

import pytest

from infracheck import checker


@pytest.fixture
def mock_lg_response(mocker):
    """Mocks the synchronous and asynchronous Looking Glass functions."""
    data = [("1.1.1.0/24", "AS13335")]
    mocker.patch("infracheck.checker.lg_data", return_value=data)
    mocker.patch("infracheck.checker.aio_lg_data", new_callable=AsyncMock, return_value=data)


def test_has_roa(mocker, mock_lg_response):
    """Tests synchronous ROA check logic."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": {"status": "valid"}}
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mocker.patch("httpx.Client.__enter__", return_value=mock_client)

    # Standard check
    prefix, is_valid = checker.has_roa("1.1.1.1", deep=False)
    assert prefix == "1.1.1.0/24"
    assert is_valid is True

    # Deep check
    prefixes, verdicts = checker.has_roa("1.1.1.1", deep=True)
    assert prefixes == ["1.1.1.0/24"]
    assert verdicts == [True]


@pytest.mark.asyncio
async def test_aio_has_roa(mocker, mock_lg_response):
    """Tests asynchronous ROA check logic."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": {"status": "valid"}}
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mocker.patch("httpx.AsyncClient.__aenter__", return_value=mock_client)

    prefix, is_valid = await checker.aio_has_roa("1.1.1.1", deep=False)
    assert prefix == "1.1.1.0/24"
    assert is_valid is True


def test_get_origins(mock_lg_response):
    """Tests synchronous origin retrieval based on LG data."""
    origins = checker.get_origins("1.1.1.1")
    assert origins == ["AS13335"]


@pytest.mark.asyncio
async def test_aio_get_origins(mock_lg_response):
    """Tests asynchronous origin retrieval based on LG data."""
    origins = await checker.aio_get_origins("1.1.1.1")
    assert origins == ["AS13335"]


def test_has_aspa(mocker):
    """Tests synchronous ASPA verification."""
    mock_resp = MagicMock()
    # Mocking a valid ASPA configuration
    mock_resp.json.return_value = {"data": {"aspa": {"providers": ["AS123"]}}}
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mocker.patch("httpx.Client.__enter__", return_value=mock_client)

    assert checker.has_aspa("AS13335") is True


def test_has_dnssec(mocker):
    """Tests synchronous shallow DNSSEC validation."""
    mock_resolve = mocker.patch("dns.resolver.resolve", return_value=True)

    result = checker.has_dnssec("example.com", deep=False)
    assert result is True
    assert mock_resolve.call_count == 2  # Called for DNSKEY and DS


@pytest.mark.asyncio
async def test_aio_has_dnssec(mocker):
    """Tests asynchronous shallow DNSSEC validation."""
    mock_resolve = mocker.patch("dns.asyncresolver.resolve", new_callable=AsyncMock)

    result = await checker.aio_has_dnssec("example.com", deep=False)
    assert result is True
    assert mock_resolve.call_count == 2
