"""Thin Docker CLI wrapper used by all scanner runners.

Hardening defaults for security tooling:
  * bind mounts are read-only by default;
  * SAST callers pass network="none" so a code scan cannot reach the network;
  * memory limit and wall-clock timeout are always enforced;
  * every failure is raised as a typed error, never silently swallowed.
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import ScannerError, ToolUnavailableError


@dataclass(frozen=True)
class Mount:
    host_path: Path
    container_path: str
    read_only: bool = True

    def to_arg(self) -> str:
        # POSIX-style host path (D:/x/y) is what Docker Desktop accepts on Windows.
        host = self.host_path.resolve().as_posix()
        mode = ":ro" if self.read_only else ":rw"
        return f"{host}:{self.container_path}{mode}"


@dataclass
class ContainerResult:
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    command: list[str] = field(default_factory=list)


class DockerClient:
    def __init__(self, exe: str = "docker"):
        self.exe = exe

    def _run(self, args: list[str], timeout_sec: int) -> subprocess.CompletedProcess | None:
        try:
            return subprocess.run(
                [self.exe, *args],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise ToolUnavailableError(
                "未找到 docker 可执行文件；请先安装并启动 Docker Desktop"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"docker 命令超时（{timeout_sec}s）: {' '.join(args[:3])}"
            ) from exc

    def server_version(self) -> str:
        cp = self._run(["version", "--format", "{{.Server.Version}}"], timeout_sec=30)
        if cp is None or cp.returncode != 0:
            detail = cp.stderr.strip()[:300] if cp else "no response"
            raise ToolUnavailableError(f"Docker 引擎未就绪: {detail}")
        return cp.stdout.strip()

    def image_exists(self, image: str) -> bool:
        cp = self._run(["image", "inspect", image], timeout_sec=30)
        return cp is not None and cp.returncode == 0

    def pull(self, image: str, timeout_sec: int = 900) -> None:
        cp = self._run(["pull", image], timeout_sec=timeout_sec)
        if cp is None or cp.returncode != 0:
            detail = cp.stderr.strip()[:400] if cp else "no response"
            raise ToolUnavailableError(f"镜像拉取失败 {image}: {detail}")

    def run_container(
        self,
        image: str,
        command: list[str],
        mounts: tuple[Mount, ...] | list[Mount] = (),
        network: str | None = None,
        mem_limit_mb: int | None = None,
        timeout_sec: int = 300,
    ) -> ContainerResult:
        args: list[str] = ["run", "--rm"]
        for mount in mounts:
            if not mount.host_path.exists():
                raise ToolUnavailableError(
                    f"挂载路径不存在: {mount.host_path}"
                )
            args += ["-v", mount.to_arg()]
        if network:
            args += ["--network", network]
        if mem_limit_mb:
            args += ["--memory", f"{mem_limit_mb}m"]
        args += [image, *command]

        cp = self._run(args, timeout_sec=timeout_sec)
        if cp is None:
            raise ScannerError(f"容器未返回结果: {image}")
        return ContainerResult(
            return_code=cp.returncode,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            command=args,
        )
