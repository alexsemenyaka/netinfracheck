from unittest.mock import AsyncMock, MagicMock

import pytest

from infracheck import utils


@pytest.fixture
def lg_fake_json():
    return {
        "data": {
            "rrcs": [
                {
                    "peers": [
                        {"prefix": "1.1.1.0/24", "asn_origin": "13335"},
                        {"prefix": "1.1.0.0/22", "asn_origin": "13335"},
                    ]
                }
            ]
        }
    }


class FakeDNSAnswer:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


def test_parse_lg_response(lg_fake_json):
    """Ensures LG parsing sorts by prefix length properly and adds AS prefix."""
    result = utils._parse_lg_response(lg_fake_json)
    assert len(result) == 2
    assert result[0] == ("1.1.1.0/24", "AS13335")
    assert result[1] == ("1.1.0.0/22", "AS13335")


def test_lg_data(mocker, lg_fake_json):
    """Tests synchronous Looking Glass data retrieval."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = lg_fake_json
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mocker.patch("httpx.Client.__enter__", return_value=mock_client)

    result = utils.lg_data("1.1.1.1")
    assert result[0] == ("1.1.1.0/24", "AS13335")


@pytest.mark.asyncio
async def test_aio_lg_data(mocker, lg_fake_json):
    """Tests asynchronous Looking Glass data retrieval."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = lg_fake_json
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mocker.patch("httpx.AsyncClient.__aenter__", return_value=mock_client)

    result = await utils.aio_lg_data("1.1.1.1")
    assert result[0] == ("1.1.1.0/24", "AS13335")


def test_resolve_domain(mocker):
    """Tests synchronous DNS resolution."""
    mocker.patch("dns.resolver.resolve", return_value=[FakeDNSAnswer("1.2.3.4")])
    result = utils.resolve_domain("example.com")
    assert result == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_aio_resolve_domain(mocker):
    """Tests asynchronous DNS resolution."""
    mocker.patch(
        "dns.asyncresolver.resolve",
        new_callable=AsyncMock,
        return_value=[FakeDNSAnswer("5.6.7.8")],
    )
    result = await utils.aio_resolve_domain("example.com")
    assert result == ["5.6.7.8"]
