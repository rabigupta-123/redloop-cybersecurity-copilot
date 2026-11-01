import httpx
import pytest

from redloop.scope import UnauthorizedTargetError
from redloop.webapp import UnsafeWebTargetError, WebAppChecker


class FakeScope:
    def __init__(self, error=None):
        self.error = error
        self.checks = []

    def check(self, target, action, port=None):
        self.checks.append((target, action, port))
        if self.error:
            raise self.error
        return type("ScopeEntry", (), {"label": "local-test"})()


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append((target, action, module, status, details, scope_entry))


def test_inspect_scoped_loopback_root_and_report_missing_headers():
    scope = FakeScope()
    audit = FakeAudit()
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"})

    checker = WebAppChecker(
        scope,
        audit,
        transport=httpx.MockTransport(respond),
    )

    report = checker.inspect("http://127.0.0.1:3000/")

    assert report.status_code == 200
    assert len(report.findings) == 6
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert scope.checks == [("127.0.0.1", "web_test", 3000)]
    assert [entry[3] for entry in audit.entries] == ["started", "success"]
    assert all(entry[5] == "local-test" for entry in audit.entries)


def test_remote_address_is_blocked_without_request():
    scope = FakeScope()
    audit = FakeAudit()
    requested = False

    def respond(request):
        nonlocal requested
        requested = True
        return httpx.Response(200)

    checker = WebAppChecker(scope, audit, transport=httpx.MockTransport(respond))

    with pytest.raises(UnsafeWebTargetError, match="loopback"):
        checker.inspect("http://192.0.2.10/")

    assert not requested
    assert scope.checks == []
    assert audit.entries[0][3] == "blocked"


def test_scope_rejection_prevents_request():
    audit = FakeAudit()
    scope = FakeScope(UnauthorizedTargetError("port not authorized"))
    requested = False

    def respond(request):
        nonlocal requested
        requested = True
        return httpx.Response(200)

    checker = WebAppChecker(scope, audit, transport=httpx.MockTransport(respond))

    with pytest.raises(UnauthorizedTargetError):
        checker.inspect("http://127.0.0.1:3000/")

    assert not requested
    assert audit.entries[0][3] == "blocked"


def test_redirect_is_reported_but_not_followed():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://example.com/"})

    checker = WebAppChecker(
        FakeScope(),
        FakeAudit(),
        transport=httpx.MockTransport(respond),
    )

    report = checker.inspect("http://127.0.0.1/")

    assert len(requests) == 1
    assert any(finding.check == "redirect-not-followed" for finding in report.findings)


def test_cookie_and_server_metadata_are_reported_without_values():
    def respond(request):
        return httpx.Response(
            200,
            headers=[
                ("set-cookie", "session=secret-value; Path=/"),
                ("server", "example-server/1.2.3"),
            ],
        )

    checker = WebAppChecker(
        FakeScope(),
        FakeAudit(),
        transport=httpx.MockTransport(respond),
    )

    report = checker.inspect("http://127.0.0.1/")
    serialized = report.model_dump_json()

    assert any(finding.check == "cookie-attributes" for finding in report.findings)
    assert any(finding.check == "technology-disclosure" for finding in report.findings)
    assert "secret-value" not in serialized
    assert "example-server/1.2.3" not in serialized


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/admin",
        "http://127.0.0.1/?q=test",
        "http://127.0.0.1:0/",
        "http://user:pass@127.0.0.1/",
        "ftp://127.0.0.1/",
    ],
)
def test_non_origin_or_nonliteral_loopback_urls_rejected(url):
    checker = WebAppChecker(FakeScope(), FakeAudit())

    with pytest.raises(UnsafeWebTargetError):
        checker.inspect(url)


def test_timeout_is_bounded():
    with pytest.raises(ValueError, match="timeout"):
        WebAppChecker(FakeScope(), FakeAudit(), timeout=30)
