from types import SimpleNamespace

import pytest

from redloop.memory import EpisodicMemory
from redloop.audit import AuditLogger
from redloop.reporting import AuditReportGenerator
from redloop.recon import (
    NmapScanner,
    ReconError,
    ReconExecutionError,
    ReconResult,
)
from redloop.scope import UnauthorizedTargetError


class FakeScope:
    def __init__(self, denied_port=None):
        self.denied_port = denied_port
        self.checked = []

    def check(self, target, action, port=None):
        self.checked.append((target, action, port))
        if port == self.denied_port:
            raise UnauthorizedTargetError(f"port {port} not allowed")
        return SimpleNamespace(label="loopback-test")


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append((target, action, module, status, details or {}))


class FakeNmap:
    def __init__(self):
        self.called = False
        self.hosts = ["127.0.0.1"]
        self.host_data = {
            "tcp": {
                8080: {
                    "state": "open",
                    "name": "http-proxy",
                    "version": "training-service",
                },
                443: {"state": "closed", "name": "https", "version": ""},
            }
        }

    def scan(self, hosts, arguments, timeout=0):
        self.called = True
        self.host = hosts
        self.arguments = arguments
        self.timeout = timeout
        return {"nmap": {"scaninfo": {"tcp": {"services": "443,8080"}}}}

    def all_hosts(self):
        return self.hosts

    def __getitem__(self, target):
        assert target == "127.0.0.1"
        return FakeHost(self.host_data)


class FakeHost:
    def __init__(self, data):
        self.data = data

    def all_protocols(self):
        return list(self.data)

    def __getitem__(self, protocol):
        return self.data[protocol]


def test_scan_parses_open_ports_and_returns_shared_result_model():
    scope = FakeScope()
    audit = FakeAudit()
    nmap = FakeNmap()
    scanner = NmapScanner(scope, audit, scanner=nmap)

    result = scanner.quick_scan("127.0.0.1", [443, 8080])

    assert isinstance(result, ReconResult)
    assert [port.port for port in result.open_ports] == [8080]
    assert [(port.port, port.state) for port in result.port_results] == [
        (443, "closed"),
        (8080, "open"),
    ]
    assert result.open_ports[0].service == "http-proxy"
    assert result.scanned_ports == [443, 8080]
    assert nmap.called
    assert nmap.host == "127.0.0.1"
    assert nmap.arguments == "-sT -Pn -sV -T3 -p 443,8080"
    assert nmap.timeout == 60
    assert scope.checked == [
        ("127.0.0.1", "recon", 443),
        ("127.0.0.1", "recon", 8080),
    ]
    assert [entry[3] for entry in audit.entries] == ["started", "success"]


def test_scope_denial_happens_before_nmap_call():
    nmap = FakeNmap()
    audit = FakeAudit()
    scanner = NmapScanner(FakeScope(denied_port=8080), audit, scanner=nmap)

    with pytest.raises(UnauthorizedTargetError):
        scanner.quick_scan("127.0.0.1", [8080])

    assert not nmap.called
    assert audit.entries[0][3] == "blocked"


@pytest.mark.parametrize("target", ["example.com", "192.0.2.10"])
def test_non_loopback_target_never_scans(target):
    nmap = FakeNmap()
    audit = FakeAudit()
    scope = FakeScope()
    scanner = NmapScanner(scope, audit, scanner=nmap)

    with pytest.raises(ReconError, match="loopback"):
        scanner.quick_scan(target, [80])

    assert not nmap.called
    assert scope.checked == []
    assert audit.entries[-1][3] == "blocked"


@pytest.mark.parametrize("ports", [[], [0], [65536], [80, 80], list(range(1, 18))])
def test_invalid_port_selection_rejected(ports):
    scanner = NmapScanner(FakeScope(), FakeAudit(), scanner=FakeNmap())

    with pytest.raises(ValueError):
        scanner.quick_scan("127.0.0.1", ports)


def test_successful_scan_is_added_to_memory(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    scanner = NmapScanner(
        FakeScope(),
        FakeAudit(),
        memory=memory,
        scanner=FakeNmap(),
    )

    scanner.quick_scan("127.0.0.1", [8080])
    matches = memory.retrieve_similar("loopback service port inventory", module="recon")

    assert len(matches) == 1
    assert matches[0].record.approach.startswith("nmap version detection")


def test_recon_audit_row_is_included_in_markdown_report(tmp_path):
    audit_db = tmp_path / "audit.sqlite"
    audit = AuditLogger(audit_db)
    scanner = NmapScanner(FakeScope(), audit, scanner=FakeNmap())

    result = scanner.quick_scan("127.0.0.1", [8080])
    report_path = AuditReportGenerator(
        audit_db, tmp_path / "reports"
    ).generate(result.target)
    report = report_path.read_text(encoding="utf-8")

    assert "nmap" in report
    assert '"open_ports": 1' in report
    assert '"port": 8080' in report
    assert '"service": "http-proxy"' in report
    assert "success" in report


def test_profile_runs_nmap_and_reports_requested_authorized_and_scanned_ports():
    scope = FakeScope()
    audit = FakeAudit()
    nmap = FakeNmap()
    scanner = NmapScanner(scope, audit, scanner=nmap)

    result = scanner.profile_target("127.0.0.1", [443, 8080])

    assert nmap.called
    assert nmap.arguments.endswith("-p 443,8080")
    assert result.requested_ports == [443, 8080]
    assert result.authorized_ports == [443, 8080]
    assert result.scanned_ports == [443, 8080]
    assert [port.port for port in result.open_ports] == [8080]
    profile_success = [
        entry for entry in audit.entries
        if entry[1] == "recon_profile" and entry[3] == "success"
    ][0]
    assert profile_success[4]["scanned_ports"] == [443, 8080]
    assert "http_checks" not in profile_success[4]


def test_profile_rejects_non_loopback_before_scope_or_network_activity():
    nmap = FakeNmap()
    scope = FakeScope()
    audit = FakeAudit()
    scanner = NmapScanner(scope, audit, scanner=nmap)

    with pytest.raises(ReconError, match="loopback"):
        scanner.profile_target("example.com", [80])

    assert not nmap.called
    assert scope.checked == []
    assert audit.entries[-1][3] == "blocked"


def test_profile_fails_closed_if_nmap_does_not_confirm_scanned_ports():
    class IncompleteScan(FakeNmap):
        def scan(self, hosts, arguments, timeout=0):
            super().scan(hosts, arguments, timeout)
            return {"nmap": {"scaninfo": {"tcp": {"services": "443"}}}}

    scanner = NmapScanner(
        FakeScope(),
        FakeAudit(),
        scanner=IncompleteScan(),
    )

    with pytest.raises(ReconExecutionError, match="did not confirm"):
        scanner.profile_target("127.0.0.1", [443, 8080])


def test_nmap_timeout_is_reported_as_failure_not_success():
    class TimedOutScan(FakeNmap):
        def scan(self, hosts, arguments, timeout=0):
            raise TimeoutError("local Nmap timed out")

    audit = FakeAudit()
    scanner = NmapScanner(FakeScope(), audit, scanner=TimedOutScan())

    with pytest.raises(ReconExecutionError, match="TimeoutError"):
        scanner.quick_scan("127.0.0.1", [443])

    assert audit.entries[-1][3] == "failed"


def test_reliability_ladder_escalation_when_filtered_and_raw_socket_open():
    """Simulate Nmap returning 'filtered' while raw socket succeeds ('open').
    Ladder must escalate through all steps and report 'open (nmap-unreliable-on-this-host)'.
    """
    class FilteredNmap(FakeNmap):
        def __init__(self):
            super().__init__()
            self.host_data = {
                "tcp": {
                    8080: {"state": "filtered", "name": "http-proxy", "version": ""},
                }
            }
            self.scan_calls = []

        def scan(self, hosts, arguments, timeout=0):
            self.called = True
            self.scan_calls.append(arguments)
            return {"nmap": {"scaninfo": {"tcp": {"services": "8080"}}}}

    scope = FakeScope()
    audit = FakeAudit()
    filtered_nmap = FilteredNmap()
    scanner = NmapScanner(
        scope, audit, scanner=filtered_nmap, raw_socket_fn=lambda t, p: ("open", None, None)
    )

    result = scanner.quick_scan("127.0.0.1", [8080])

    assert len(result.port_results) == 1
    port_item = result.port_results[0]
    assert port_item.state == "open (nmap-unreliable-on-this-host)"
    assert [p.port for p in result.open_ports] == [8080]
    assert result.raw_summary == "1 open port(s)"
    assert port_item.confidence == "cross-checked, Nmap environment-limited"

    success_entry = [e for e in audit.entries if e[3] == "success"][0]
    escalations = success_entry[4]["escalations"]
    assert len(escalations) == 1
    esc = escalations[0]
    assert esc["port"] == 8080
    assert esc["final_state"] == "open"
    assert esc["final_source"] == "raw_socket_crosscheck"
    assert esc["confidence"] == "cross-checked, Nmap environment-limited"
    techniques_tried = [a["technique"] for a in esc["attempts"]]
    assert techniques_tried == [
        "-sT default",
        "-Pn",
        "--disable-arp-ping",
        "-sT with explicit --source-port",
        "raw_socket_crosscheck",
    ]


def test_reliability_ladder_consecutive_agreement_stops_early():
    """When two consecutive ladder techniques agree on open/closed, stop immediately."""
    class AgreingNmap(FakeNmap):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def scan(self, hosts, arguments, timeout=0):
            self.calls += 1
            if self.calls == 1:
                state = "filtered"
            elif self.calls == 2:
                state = "open"  # Step a (-Pn) returns open
            else:
                state = "open"  # Step b (--disable-arp-ping) also returns open -> agreement
            self.host_data = {"tcp": {8080: {"state": state, "name": "http", "version": ""}}}
            return {"nmap": {"scaninfo": {"tcp": {"services": "8080"}}}}

    scope = FakeScope()
    audit = FakeAudit()
    agreed_nmap = AgreingNmap()
    raw_socket_called = []
    scanner = NmapScanner(
        scope, audit, scanner=agreed_nmap,
        raw_socket_fn=lambda t, p: raw_socket_called.append((t, p)) or ("closed", None, None)
    )

    result = scanner.quick_scan("127.0.0.1", [8080])

    assert result.port_results[0].state == "open"
    success_entry = [e for e in audit.entries if e[3] == "success"][0]
    esc = success_entry[4]["escalations"][0]
    assert esc["final_state"] == "open"
    assert esc["final_source"] == "--disable-arp-ping"
    assert len(raw_socket_called) == 0
    assert len(esc["attempts"]) == 3


def test_reliability_ladder_never_touches_unauthorized_port():
    """Confirm the ladder strictly checks scope at every step and refuses unauthorized ports."""
    from redloop.recon import PortResult

    scope = FakeScope(denied_port=9999)
    audit = FakeAudit()
    scanner = NmapScanner(scope, audit, scanner=FakeNmap())

    port_item = PortResult(port=9999, protocol="tcp", state="filtered")
    with pytest.raises(UnauthorizedTargetError):
        scanner._run_reliability_ladder("127.0.0.1", port_item)

    with pytest.raises(UnauthorizedTargetError):
        scanner.quick_scan("127.0.0.1", [9999])


def test_reliability_ladder_capped_at_4_attempts_max():
    """Confirm ladder executes at most 4 retry steps per port, never loops indefinitely."""
    from redloop.recon import PortResult

    class DisagreeingNmap(FakeNmap):
        def __init__(self):
            super().__init__()
            self.call_count = 0

        def scan(self, hosts, arguments, timeout=0):
            self.call_count += 1
            state = "open" if self.call_count % 2 == 0 else "filtered"
            self.host_data = {"tcp": {8080: {"state": state, "name": "http", "version": ""}}}
            return {"nmap": {"scaninfo": {"tcp": {"services": "8080"}}}}

    scope = FakeScope()
    audit = FakeAudit()
    scanner = NmapScanner(
        scope, audit, scanner=DisagreeingNmap(),
        raw_socket_fn=lambda t, p: ("filtered", None, None)
    )

    item = PortResult(port=8080, protocol="tcp", state="filtered")
    escalation = scanner._run_reliability_ladder("127.0.0.1", item)

    ladder_steps = [a for a in escalation["attempts"] if a["technique"] != "-sT default"]
    assert len(ladder_steps) == 4, f"Expected exactly 4 ladder steps, got {len(ladder_steps)}"

