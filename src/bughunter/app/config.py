"""Typed settings loaded from assets/config/default.toml + environment variables.

Override examples (env prefix BUGHUNTER_, nested delimiter __):
  BUGHUNTER_GENERAL__HOME=D:/bughunter-data
  BUGHUNTER_LLM__MODEL=qwen2.5:14b
"""

from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TOML = PROJECT_ROOT / "assets" / "config" / "default.toml"


class GeneralSettings(BaseModel):
    home: str = "data"
    log_dir: str = "logs"
    actor: str = "local"


class LLMSettings(BaseModel):
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "qwen2.5:7b"
    api_key_env: str = "BUGHUNTER_LLM_API_KEY"
    timeout_sec: int = 60
    max_retries: int = 2


class RateLimitSettings(BaseModel):
    requests_per_sec: float = 1.0
    daily_budget: int = 500


class ScanSettings(BaseModel):
    active_scan_enabled: bool = False
    semgrep_backend: str = "docker"
    zap_network: str = "bughunter_lab"
    zap_spider_depth: int = 5
    zap_threads: int = 2


class EvidenceSettings(BaseModel):
    response_max_bytes: int = 4096


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BUGHUNTER_",
        env_nested_delimiter="__",
        toml_file=str(DEFAULT_TOML),
        extra="ignore",
    )

    general: GeneralSettings = Field(default_factory=GeneralSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    ratelimit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # Init args > environment > TOML file > secrets
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    def home_dir(self) -> Path:
        path = Path(self.general.home)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path

    def log_dir(self) -> Path:
        path = Path(self.general.log_dir)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path

    def db_path(self) -> Path:
        return self.home_dir() / "bughunter.db"

    def llm_api_key(self) -> str:
        """API key is read from an environment variable, never stored."""
        import os

        return os.environ.get(self.llm.api_key_env, "")
