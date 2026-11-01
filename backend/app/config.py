"""Application configuration loaded from environment variables."""
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", extra="ignore")

    app_env: str = "development"
    app_name: str = "CYBERGUARD"
    app_url: str = "http://localhost:5173"
    api_base_url: str = "http://localhost:8000"

    database_url: str = f"sqlite:///{(BASE_DIR / 'aegis_sentinel.db').as_posix()}"
    redis_url: str = ""

    jwt_secret_key: str = "dev-only-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 720
    encryption_key: str = "dev-only-insecure-encryption-key"

    # Threat intelligence connectors
    nvd_api_key: str = ""
    cisa_kev_enabled: bool = True
    epss_enabled: bool = True
    mitre_attack_enabled: bool = True
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    csirt_enabled: bool = True

    # DeepSeek chat provider. The key is read only here, server-side.
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_timeout_seconds: int = 90
    deepseek_max_output_tokens: int = 1600
    deepseek_temperature: float = 0.2
    deepseek_retries: int = 2

    # Notifications
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""

    # Feature switches
    enable_live_threat_feeds: bool = True
    seed_intelligence_corpus: bool = True
    enable_ai_analysis: bool = True
    enable_email_alerts: bool = False
    enable_threat_correlation: bool = True

    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

    @field_validator("deepseek_base_url")
    @classmethod
    def _https_provider_url(cls, value: str) -> str:
        """The bearer key must never be sent in cleartext; http is allowed only for a local proxy."""
        trimmed = value.strip().rstrip("/")
        parts = urlsplit(trimmed)
        is_local = parts.hostname in {"localhost", "127.0.0.1", "::1"}
        if parts.scheme == "https" or (parts.scheme == "http" and is_local):
            return trimmed
        raise ValueError("DEEPSEEK_BASE_URL must be an https:// URL (http is permitted only for localhost)")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def deepseek_configured(self) -> bool:
        return bool(self.deepseek_api_key.strip())

    @property
    def deepseek_host(self) -> str:
        """Host only — used for status display so the base URL is never ambiguous."""
        return urlsplit(self.deepseek_base_url).netloc or "not-set"

    def connector_status(self) -> dict[str, bool]:
        return {
            "nvd": True,
            "cisa_kev": self.cisa_kev_enabled,
            "epss": self.epss_enabled,
            "mitre_attack": self.mitre_attack_enabled,
            "otx": bool(self.otx_api_key),
            "virustotal": bool(self.virustotal_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
            "greynoise": bool(self.greynoise_api_key),
            "csirt": self.csirt_enabled,
            "deepseek": self.deepseek_configured,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
