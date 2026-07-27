"""Injectable HTTP JSON transport tests; no network access."""

import requests
import pytest

from ioc_rejudge.providers.transport import RequestsTransport, TransportError


class FakeResponse:
    def __init__(self, payload=None, *, status_code=200, http_error=False, json_error=None):
        self.payload = payload
        self.status_code = status_code
        self.http_error = http_error
        self.json_error = json_error

    def raise_for_status(self):
        if self.http_error:
            raise requests.HTTPError(
                f"unsafe upstream detail for {self.status_code}",
                response=self,
            )

    def json(self):
        if self.json_error is not None:
            raise self.json_error
        return self.payload


class FakeSession:
    def __init__(self, response=None, *, get_error=None, post_error=None):
        self.response = response
        self.get_error = get_error
        self.post_error = post_error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        if self.get_error:
            raise self.get_error
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        if self.post_error:
            raise self.post_error
        return self.response


def test_get_json_returns_payload_and_passes_exact_request_shape():
    session = FakeSession(FakeResponse({"ok": True}))
    transport = RequestsTransport(session)
    result = transport.get_json(
        "https://api.invalid/items",
        headers={"Api-Key": "secret"},
        params={"ioc": "example.invalid"},
        timeout=7,
    )
    assert result == {"ok": True}
    assert session.calls == [(
        "get",
        "https://api.invalid/items",
        {
            "headers": {"Api-Key": "secret"},
            "params": {"ioc": "example.invalid"},
            "timeout": 7,
        },
    )]


def test_post_json_returns_list_and_passes_body_as_json():
    session = FakeSession(FakeResponse([{"ok": True}]))
    transport = RequestsTransport(session)
    result = transport.post_json(
        "https://api.invalid/query",
        headers={"Authorization": "secret"},
        body={"params": ["example.invalid"]},
        timeout=11,
    )
    assert result == [{"ok": True}]
    assert session.calls[0] == (
        "post",
        "https://api.invalid/query",
        {
            "headers": {"Authorization": "secret"},
            "json": {"params": ["example.invalid"]},
            "timeout": 11,
        },
    )


@pytest.mark.parametrize(
    ("method", "exception", "kind"),
    [
        ("get", requests.Timeout("upstream timeout secret"), "timeout"),
        ("get", requests.ConnectionError("connection secret"), "connection"),
        ("post", requests.Timeout("upstream timeout secret"), "timeout"),
        ("post", requests.ConnectionError("connection secret"), "connection"),
    ],
)
def test_request_failures_have_distinct_safe_kinds(method, exception, kind):
    kwargs = {f"{method}_error": exception}
    transport = RequestsTransport(FakeSession(**kwargs))
    call = transport.get_json if method == "get" else transport.post_json
    with pytest.raises(TransportError) as caught:
        call(
            "https://user:password@api.invalid/path?token=query-secret",
            headers={"Authorization": "SENTINEL_HEADER_SECRET"},
            **({"params": {"x": 1}} if method == "get" else {"body": {"token": "SENTINEL_BODY_SECRET"}}),
        )
    error = caught.value
    assert error.kind == kind
    assert error.status_code is None
    rendered = f"{error!r} {error}"
    assert "SENTINEL" not in rendered
    assert "password" not in rendered
    assert "query-secret" not in rendered
    assert "upstream timeout secret" not in rendered
    assert "connection secret" not in rendered
    assert "https://api.invalid/path" in rendered


@pytest.mark.parametrize("status_code", [401, 500])
def test_http_error_keeps_status_without_response_or_header_secrets(status_code):
    sentinel = "SENTINEL_HTTP_SECRET_7d1b"
    response = FakeResponse(status_code=status_code, http_error=True)
    transport = RequestsTransport(FakeSession(response))
    with pytest.raises(TransportError) as caught:
        transport.get_json(
            "https://api.invalid/private?token=" + sentinel,
            headers={"Authorization": "Bearer " + sentinel},
        )
    error = caught.value
    assert error.kind == "http"
    assert error.status_code == status_code
    assert str(status_code) in str(error)
    assert sentinel not in str(error)
    assert sentinel not in repr(error)


def test_bad_json_is_json_decode_with_safe_endpoint_and_status():
    sentinel = "SENTINEL_JSON_SECRET_b833"
    decode_error = requests.exceptions.JSONDecodeError(
        f"bad JSON containing {sentinel}",
        "not-json",
        0,
    )
    response = FakeResponse(status_code=200, json_error=decode_error)
    transport = RequestsTransport(FakeSession(response))
    with pytest.raises(TransportError) as caught:
        transport.post_json(
            "https://api.invalid/query?api_key=" + sentinel,
            headers={"Api-Key": sentinel},
            body={"secret": sentinel},
        )
    error = caught.value
    assert error.kind == "json_decode"
    assert error.status_code == 200
    assert sentinel not in str(error)
    assert sentinel not in repr(error)


def test_programming_error_is_not_reclassified():
    class BrokenResponse(FakeResponse):
        def raise_for_status(self):
            raise RuntimeError("programming bug")

    transport = RequestsTransport(FakeSession(BrokenResponse()))
    with pytest.raises(RuntimeError, match="programming bug"):
        transport.get_json("https://api.invalid/items")


def test_transport_error_attributes_and_repr_are_stable():
    error = TransportError("http", "HTTP request failed", status_code=503)
    assert error.kind == "http"
    assert error.status_code == 503
    assert str(error) == "HTTP request failed"
    assert "HTTP request failed" in repr(error)
