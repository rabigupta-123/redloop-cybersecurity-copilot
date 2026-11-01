"""DockerSandbox: isolated code execution for RedLoop's self-healing loop.

Security invariants (fail-closed):
  * network_mode is always 'none'; all sandbox networking is disabled.
  * No bind-mount of the host project directory, home directory, or any
    sensitive path — only a temp directory with the generated script, mounted
    read-only at /work.
  * Hard CPU / memory / time limits; containers are ephemeral (removed after
    logs are collected).
  * Runs as non-root inside the container (UID 1000) with all capabilities dropped.
"""

from __future__ import annotations

import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

import docker
from docker.errors import ContainerError, ImageNotFound, DockerException
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout

from redloop.config import settings

MAX_SCRIPT_BYTES = 1_000_000
MAX_LOG_BYTES = 1_000_000
_MEMORY_LIMIT_RE = re.compile(r"^[1-9][0-9]*(?:k|m|g)$", re.IGNORECASE)


def validate_network_policy(
    configured_network: str,
    requested_network: str | None = None,
) -> str:
    """Allow only Docker's network-disabled mode until a network is reviewed."""
    network = requested_network if requested_network is not None else configured_network
    if not isinstance(network, str) or network != "none":
        raise ValueError(
            "Sandbox networking is disabled; only the exact network mode 'none' "
            "is permitted."
        )
    return network


@dataclass(slots=True)
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    container_id: str | None = None


class DockerSandbox:
    """Hardened container runner for LLM-generated Python/bash."""

    def __init__(
        self,
        image: str | None = None,
        timeout: int | None = None,
        network: str | None = None,
        mem_limit: str | None = None,
        cpu_limit: float | None = None,
    ):
        if timeout is not None and (
            isinstance(timeout, bool) or not 1 <= timeout <= 3_600
        ):
            raise ValueError("timeout must be between 1 and 3600 seconds")
        if mem_limit is not None and not _MEMORY_LIMIT_RE.fullmatch(mem_limit):
            raise ValueError("mem_limit must be a positive Docker size such as 512m")
        configured_network = (
            settings.sandbox_network if network is None else network
        )
        self.network = validate_network_policy(configured_network)
        selected_cpu_limit = (
            settings.sandbox_cpu_limit if cpu_limit is None else cpu_limit
        )
        if (
            isinstance(selected_cpu_limit, bool)
            or not isinstance(selected_cpu_limit, (int, float))
            or not 0 < selected_cpu_limit <= 4
        ):
            raise ValueError("cpu_limit must be greater than 0 and at most 4")
        selected_timeout = (
            settings.sandbox_timeout if timeout is None else timeout
        )
        if (
            isinstance(selected_timeout, bool)
            or not isinstance(selected_timeout, int)
            or not 1 <= selected_timeout <= 3_600
        ):
            raise ValueError("timeout must be between 1 and 3600 seconds")
        selected_memory = (
            settings.sandbox_memory_limit if mem_limit is None else mem_limit
        )
        if not isinstance(selected_memory, str) or not _MEMORY_LIMIT_RE.fullmatch(
            selected_memory
        ):
            raise ValueError("mem_limit must be a positive Docker size such as 512m")
        self.client = docker.from_env()
        self.image = image or settings.sandbox_image
        self.timeout = selected_timeout
        self.mem_limit = selected_memory
        self.cpu_limit = selected_cpu_limit

    def _ensure_image(self) -> None:
        """Pull the sandbox image if not present locally."""
        try:
            self.client.images.get(self.image)
        except ImageNotFound:
            self.client.images.pull(self.image)

    def run(
        self,
        code: str,
        language: str = "python",
        allowed_network: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute `code` in an isolated container and return the result."""
        net_mode = validate_network_policy(self.network, allowed_network)
        if not isinstance(code, str) or len(code.encode("utf-8")) > MAX_SCRIPT_BYTES:
            raise ValueError(f"code must be text no larger than {MAX_SCRIPT_BYTES} bytes")
        if env:
            raise ValueError(
                "Custom environment variables are disabled to prevent host secrets "
                "from being passed into the sandbox."
            )
        if language == "python":
            script_name = "task.py"
            cmd = ["python", "-u", f"/work/{script_name}"]
        elif language == "bash":
            script_name = "task.sh"
            cmd = ["bash", "-eu", f"/work/{script_name}"]
        else:
            raise ValueError(f"Unsupported language: {language}")
        self._ensure_image()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script_path = tmp / script_name
            script_path.write_text(code, encoding="utf-8")
            script_path.chmod(0o500)  # read+execute only

            # Bind the temp dir read-only at /work inside the container
            volumes = {str(tmp): {"bind": "/work", "mode": "ro"}}

            container_id = f"redloop-{uuid.uuid4().hex[:12]}"
            container = None
            result: ExecutionResult | None = None
            cleanup_error: DockerException | None = None
            try:
                container = self.client.containers.run(
                    self.image,
                    command=cmd,
                    volumes=volumes,
                    network_mode=net_mode,
                    mem_limit=self.mem_limit,
                    cpu_quota=int(self.cpu_limit * 100_000),
                    cpu_period=100_000,
                    pids_limit=128,
                    log_config={
                        "type": "json-file",
                        "config": {"max-size": "1m", "max-file": "1"},
                    },
                    working_dir="/work",
                    user="1000:1000",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    read_only=True,  # Root filesystem is read-only.
                    environment={},
                    name=container_id,
                    detach=True,
                    remove=False,  # we remove manually after collecting logs
                )

                try:
                    exit_status = container.wait(timeout=self.timeout)
                    exit_code = exit_status.get("StatusCode", -1)
                    timeout_message = ""
                except ReadTimeout:
                    container.kill()
                    exit_code = -1
                    timeout_message = (
                        f"Execution timed out after {self.timeout} seconds."
                    )
                except RequestsConnectionError as exc:
                    if "read timed out" not in str(exc).casefold():
                        raise
                    container.kill()
                    exit_code = -1
                    timeout_message = (
                        f"Execution timed out after {self.timeout} seconds."
                    )

                stdout = container.logs(stdout=True, stderr=False)[
                    :MAX_LOG_BYTES
                ].decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True)[
                    :MAX_LOG_BYTES
                ].decode("utf-8", errors="replace")
                if timeout_message:
                    stderr = f"{stderr}\n{timeout_message}".strip()

                result = ExecutionResult(
                    success=exit_code == 0,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    container_id=container.id[:12],
                )

            except ContainerError as e:
                result = ExecutionResult(
                    success=False,
                    stdout="",
                    stderr=str(e),
                    exit_code=e.exit_status or -1,
                )
            except DockerException as e:
                result = ExecutionResult(
                    success=False,
                    stdout="",
                    stderr=f"Docker error: {e}",
                    exit_code=-1,
                )
            finally:
                if container is not None:
                    try:
                        container.remove(force=True)
                    except DockerException as exc:
                        cleanup_error = exc

            if cleanup_error is not None:
                prior_stderr = result.stderr if result is not None else ""
                result = ExecutionResult(
                    success=False,
                    stdout=result.stdout if result is not None else "",
                    stderr=f"{prior_stderr}\nDocker cleanup error: {cleanup_error}".strip(),
                    exit_code=-1,
                    container_id=(
                        result.container_id if result is not None else container_id
                    ),
                )
            if result is None:
                raise RuntimeError("Sandbox execution completed without a result")
            return result


# -- Default sandbox image builder -------------------------------------------
# This creates the `redloop-sandbox` image the first time it's needed.
# It's a minimal Alpine + Python image with no network tools by design.

DEFAULT_SANDBOX_DOCKERFILE = """
FROM alpine:3.20
RUN apk add --no-cache python3 bash
RUN adduser -D -u 1000 sandbox
USER sandbox
WORKDIR /work
ENTRYPOINT []
"""


def build_sandbox_image(tag: str = "redloop-sandbox") -> None:
    """Build the default sandbox image locally or raise the Docker error."""
    import tarfile
    import io

    client = docker.from_env()
    dockerfile_bytes = DEFAULT_SANDBOX_DOCKERFILE.encode("utf-8")
    tarstream = io.BytesIO()
    with tarfile.open(fileobj=tarstream, mode="w") as tar:
        info = tarfile.TarInfo(name="Dockerfile")
        info.size = len(dockerfile_bytes)
        tar.addfile(info, io.BytesIO(dockerfile_bytes))
    tarstream.seek(0)

    client.images.build(fileobj=tarstream, tag=tag, rm=True)