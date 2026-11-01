from types import SimpleNamespace

import pytest
from docker.errors import DockerException, ImageNotFound
from requests.exceptions import ReadTimeout

from redloop.sandbox import DockerSandbox, validate_network_policy


@pytest.mark.parametrize("network", ["none", ""])
def test_sandbox_network_policy_only_allows_disabled_mode(network):
    if network == "none":
        assert validate_network_policy(network) == "none"
    else:
        with pytest.raises(ValueError, match="networking is disabled"):
            validate_network_policy(network)


@pytest.mark.parametrize(
    "network",
    ["host", "bridge", "container:other", "custom-redloop-net", "None"],
)
def test_sandbox_rejects_host_and_arbitrary_network_modes_before_docker(
    monkeypatch, network
):
    docker_called = False

    def from_env():
        nonlocal docker_called
        docker_called = True
        raise AssertionError("Docker must not be contacted for invalid modes")

    monkeypatch.setattr("redloop.sandbox.docker.from_env", from_env)

    with pytest.raises(ValueError, match="networking is disabled"):
        DockerSandbox(network=network)

    assert not docker_called


def test_sandbox_rejects_caller_network_and_env_before_image_lookup(monkeypatch):
    class FakeClient:
        images = SimpleNamespace(get=lambda _image: pytest.fail("unexpected image lookup"))

    monkeypatch.setattr("redloop.sandbox.docker.from_env", lambda: FakeClient())
    sandbox = DockerSandbox()

    with pytest.raises(ValueError, match="networking is disabled"):
        sandbox.run("pass", allowed_network="host")
    with pytest.raises(ValueError, match="environment variables are disabled"):
        sandbox.run("pass", env={"API_KEY": "not-really-a-secret"})


def test_sandbox_surfaces_image_pull_failures(monkeypatch):
    class FakeImages:
        def get(self, _image):
            raise ImageNotFound("image missing")

        def pull(self, _image):
            raise DockerException("image pull failed")

    monkeypatch.setattr(
        "redloop.sandbox.docker.from_env",
        lambda: SimpleNamespace(images=FakeImages()),
    )
    sandbox = DockerSandbox()

    with pytest.raises(DockerException, match="image pull failed"):
        sandbox.run("print('not started')")


def test_sandbox_runs_with_network_disabled_and_enforced_container_limits(
    monkeypatch,
):
    calls = {}

    class FakeContainer:
        id = "container-id-123456"

        def wait(self, timeout):
            calls["timeout"] = timeout
            return {"StatusCode": 0}

        def logs(self, stdout, stderr):
            return b"ok"

        def remove(self, force):
            calls["removed"] = force

    class FakeClient:
        images = SimpleNamespace(get=lambda _image: object())

        def __init__(self):
            self.containers = SimpleNamespace(run=self.run)

        def run(self, image, **kwargs):
            calls["image"] = image
            calls["container_options"] = kwargs
            return FakeContainer()

    monkeypatch.setattr("redloop.sandbox.docker.from_env", FakeClient)
    sandbox = DockerSandbox(timeout=2, mem_limit="128m", cpu_limit=0.5)

    result = sandbox.run("print('ok')")

    options = calls["container_options"]
    assert result.success
    assert result.stdout == "ok"
    assert options["network_mode"] == "none"
    assert options["mem_limit"] == "128m"
    assert options["cpu_quota"] == 50_000
    assert options["pids_limit"] == 128
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["volumes"][next(iter(options["volumes"]))]["mode"] == "ro"
    assert options["environment"] == {}
    assert calls["timeout"] == 2
    assert calls["removed"] is True


def test_sandbox_timeout_kills_container_and_reports_timeout(monkeypatch):
    calls = {"killed": False, "removed": False}

    class FakeContainer:
        id = "container-timeout"

        def wait(self, timeout):
            raise ReadTimeout("wait timed out")

        def kill(self):
            calls["killed"] = True

        def logs(self, stdout, stderr):
            return b"partial output"

        def remove(self, force):
            calls["removed"] = force

    class FakeClient:
        images = SimpleNamespace(get=lambda _image: object())

        def __init__(self):
            self.containers = SimpleNamespace(
                run=lambda _image, **_kwargs: FakeContainer()
            )

    monkeypatch.setattr("redloop.sandbox.docker.from_env", FakeClient)
    result = DockerSandbox(timeout=2).run("print('partial')")

    assert not result.success
    assert result.exit_code == -1
    assert "timed out after 2 seconds" in result.stderr
    assert calls == {"killed": True, "removed": True}


def test_sandbox_cleanup_failure_changes_success_result_to_failure(monkeypatch):
    class FakeContainer:
        id = "container-cleanup"

        def wait(self, timeout):
            return {"StatusCode": 0}

        def logs(self, stdout, stderr):
            return b"ok"

        def remove(self, force):
            raise DockerException("remove failed")

    class FakeClient:
        images = SimpleNamespace(get=lambda _image: object())

        def __init__(self):
            self.containers = SimpleNamespace(
                run=lambda _image, **_kwargs: FakeContainer()
            )

    monkeypatch.setattr("redloop.sandbox.docker.from_env", FakeClient)
    result = DockerSandbox().run("print('ok')")

    assert not result.success
    assert "Docker cleanup error: remove failed" in result.stderr
    assert result.container_id == "container-cl"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": 3601}, "timeout"),
        ({"mem_limit": "0m"}, "mem_limit"),
        ({"cpu_limit": 0}, "cpu_limit"),
        ({"cpu_limit": 5}, "cpu_limit"),
    ],
)
def test_sandbox_invalid_resource_limits_fail_before_docker(
    monkeypatch, kwargs, message
):
    monkeypatch.setattr(
        "redloop.sandbox.docker.from_env",
        lambda: pytest.fail("Docker must not be created for invalid limits"),
    )

    with pytest.raises(ValueError, match=message):
        DockerSandbox(**kwargs)
