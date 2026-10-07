"""Configuration de l'application : chemins, profils de scan, parametres de
securite operationnelle. Charge les valeurs par defaut depuis
`config/defaults/*.yaml`, surchargeables par variables d'environnement
prefixees `ADSEC_` ou par un fichier `~/.adsec/config.yaml`."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from adsec.core.scheduler.scheduler import SchedulerSafetyConfig

_DEFAULTS_DIR = Path(__file__).parent / "defaults"
_DEFAULT_HOME = Path.home() / ".adsec"


class ProfileDefinition(BaseModel):
    description: str
    allowed_categories: list[str]
    max_workers: int
    max_requests_per_second: float


def load_profile_definitions() -> dict[str, ProfileDefinition]:
    raw = yaml.safe_load((_DEFAULTS_DIR / "profiles.yaml").read_text(encoding="utf-8"))
    return {name: ProfileDefinition(**data) for name, data in raw.items()}


def load_default_safety_config() -> SchedulerSafetyConfig:
    raw = yaml.safe_load((_DEFAULTS_DIR / "safety.yaml").read_text(encoding="utf-8"))
    safety = raw.get("safety", {})
    return SchedulerSafetyConfig(**safety)


def default_intrusive_actions_enabled() -> bool:
    raw = yaml.safe_load((_DEFAULTS_DIR / "safety.yaml").read_text(encoding="utf-8"))
    return bool(raw.get("intrusive_actions", {}).get("enabled", False))


class AppSettings(BaseSettings):
    """Parametres globaux de l'application, surchargeables via variables
    d'environnement ADSEC_* (ex: ADSEC_DATA_DIR, ADSEC_LOG_LEVEL)."""

    model_config = SettingsConfigDict(env_prefix="ADSEC_", extra="ignore")

    data_dir: Path = Field(default=_DEFAULT_HOME)
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")  # "json" ou "console"
    default_operator: str | None = Field(default=None)

    @property
    def database_path(self) -> Path:
        return self.data_dir / "adsec.sqlite3"

    @property
    def audit_log_dir(self) -> Path:
        return self.data_dir / "audit"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_directories(self) -> None:
        for path in (self.data_dir, self.audit_log_dir, self.reports_dir):
            path.mkdir(parents=True, exist_ok=True)


def load_settings() -> AppSettings:
    return AppSettings()
