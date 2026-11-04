"""Semgrep SAST runner (Docker, offline).

Red lines enforced here:
  * code and rules are mounted read-only;
  * the container runs with --network none, and telemetry is disabled
    (--metrics=off), so a code scan cannot reach the network;
  * only the bundled custom rules directory is used by default. The registry
    "auto" config needs internet and is therefore NOT enabled (it would defeat
    the offline guarantee); extra local configs can be passed explicitly.
"""

from pathlib import Path

from ..core.enums import Tool
from ..core.errors import ScannerError, ToolUnavailableError
from ..infra.docker import DockerClient, Mount
from .base import RawScanResult, ToolRunner
from .normalize import normalize_semgrep

SRC_CONTAINER = "/src"
RULES_CONTAINER = "/rules"

# Exit codes that still come with a usable JSON report (parse skips etc.).
USABLE_EXIT_CODES = frozenset({0, 1, 4})


class SemgrepRunner(ToolRunner):
    def __init__(
        self,
        docker: DockerClient,
        image: str,
        rules_dir: Path,
        mem_limit_mb: int = 2048,
        timeout_sec: int = 300,
        extra_configs: tuple[str, ...] = (),
    ):
        self.docker = docker
        self.image = image
        self.rules_dir = Path(rules_dir)
        self.mem_limit_mb = mem_limit_mb
        self.timeout_sec = timeout_sec
        self.configs = [RULES_CONTAINER, *extra_configs]

    @property
    def tool(self) -> str:
        return Tool.SEMGREP.value

    def _command(self) -> list[str]:
        command = ["semgrep", "scan", "--json", "--metrics=off", "--quiet"]
        for config in self.configs:
            command += ["--config", config]
        command.append(SRC_CONTAINER)
        return command

    def ensure_ready(self) -> None:
        self.docker.server_version()
        if not self.docker.image_exists(self.image):
            raise ToolUnavailableError(
                f"缺少 Docker 镜像 {self.image}；请先执行 `docker pull {self.image}`。"
                " 离线扫描仅使用内置自定义规则，不使用需要联网的 --config auto。"
            )

    def run(self, code_path: Path) -> RawScanResult:
        code_path = Path(code_path)
        if not code_path.is_dir():
            raise ToolUnavailableError(f"待扫描代码目录不存在或不是目录: {code_path}")
        if not self.rules_dir.is_dir():
            raise ToolUnavailableError(f"自定义规则目录不存在: {self.rules_dir}")

        self.ensure_ready()
        result = self.docker.run_container(
            image=self.image,
            command=self._command(),
            mounts=[
                Mount(code_path, SRC_CONTAINER, read_only=True),
                Mount(self.rules_dir, RULES_CONTAINER, read_only=True),
            ],
            network="none",
            mem_limit_mb=self.mem_limit_mb,
            timeout_sec=self.timeout_sec,
        )

        stdout = result.stdout.strip()
        if stdout.startswith("{"):
            # Usable JSON even if some files were skipped (exit 4).
            return normalize_semgrep(result.stdout)
        raise ScannerError(
            f"Semgrep 执行失败 exit={result.return_code}; "
            f"stderr={result.stderr.strip()[:500]}"
        )
