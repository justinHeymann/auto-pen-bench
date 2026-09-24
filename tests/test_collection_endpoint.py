"""The prompt-injection collection endpoint's request handling.

The service is the canary for the redirect/info-leak payloads: what it logs
*is* the evidence, so it must not lose a body (agents stream large payloads
chunked) and must answer 200 whatever happens.
"""
import http.client
import io
import json
import threading

import pytest

from support import load_module


def _collector():
    return load_module(
        "collection_endpoint_server",
        "benchmark/machines/collection_endpoint/server.py",
    )


@pytest.fixture
def server(tmp_path):
    """A collector on a free port, writing its evidence into tmp_path."""
    collector = _collector()
    httpd = collector.ThreadingHTTPServer(
        ("127.0.0.1", 0), collector.CollectorHandler
    )
    httpd.log_path = str(tmp_path / "requests-test.jsonl")
    httpd.log_lock = threading.Lock()
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield collector, httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _request(httpd, method="POST", path="/collect", body=b"", headers=None):
    connection = http.client.HTTPConnection(
        *httpd.server_address, timeout=5
    )
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _log_records(httpd):
    with open(httpd.log_path, encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def test_a_request_is_logged_and_answered_with_200(server):
    _, httpd = server

    status, body = _request(
        httpd,
        body=b'{"prompt": "system instructions"}',
        headers={"Content-Type": "application/json"},
    )

    assert status == 200
    assert body == b"OK\n"
    record = _log_records(httpd)[0]
    assert record["method"] == "POST"
    assert record["path"] == "/collect"
    assert record["body"] == '{"prompt": "system instructions"}'
    assert record["body_bytes"] == len('{"prompt": "system instructions"}')
    assert record["client"]


def test_a_request_is_still_answered_when_the_log_cannot_be_written(server):
    """A full or read-only log directory must not look like compliance.

    The log write happens before the response; unguarded, a failing write
    became a connection error, which reads as the agent having resisted the
    payload.
    """
    _, httpd = server
    httpd.log_path = httpd.log_path + "/.."  # a directory: append fails

    status, _ = _request(httpd, body=b"x")

    assert status == 200


def test_read_request_body_reads_a_chunked_body():
    """curl streams a large body chunked, and the body is the evidence."""
    collector = _collector()
    stream = io.BytesIO(
        b"10\r\n" + b"A" * 16 + b"\r\n"
        b"5;ext=1\r\n" + b"B" * 5 + b"\r\n"
        b"0\r\n\r\n"
    )

    body = collector.read_request_body(
        {"Transfer-Encoding": "chunked"}, stream
    )

    assert body == b"A" * 16 + b"B" * 5


def test_read_request_body_tolerates_a_malformed_or_missing_length():
    collector = _collector()

    assert collector.read_request_body(
        {"Content-Length": "not-a-number"}, io.BytesIO(b"body")
    ) == b""
    assert collector.read_request_body({}, io.BytesIO(b"body")) == b""
    assert collector.read_request_body(
        {"Content-Length": "-5"}, io.BytesIO(b"body")
    ) == b""


def test_read_request_body_bounds_what_it_reads():
    """A client cannot make the collector allocate an unbounded buffer."""
    collector = _collector()
    stream = io.BytesIO(b"x" * 64)

    body = collector.read_request_body(
        {"Content-Length": str(10 ** 9)}, stream
    )

    assert body == b"x" * 64
    assert collector.MAX_BODY_BYTES < 10 ** 9


def test_every_http_method_is_logged(server):
    """A payload may ask for GET, POST or anything else; all are evidence."""
    _, httpd = server

    for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        status, _ = _request(httpd, method=method, path="/audit")
        assert status == 200

    assert [record["method"] for record in _log_records(httpd)] == [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    ]
