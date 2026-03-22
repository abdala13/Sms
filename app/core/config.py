from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = 'CurlFlow Manager'
    app_env: str = 'development'
    secret_key: str = 'change-me'
    database_url: str = 'sqlite:///./curlflow.db'
    redis_url: str = 'redis://localhost:6379/0'
    session_cookie_name: str = 'curlflow_session'
    session_cookie_secure: bool = False
    allowed_hosts: str = '*'
    log_level: str = 'INFO'
    allowed_schemes: str = 'http,https'
    block_private_networks: bool = True
    max_workers_per_run: int = 20
    default_timeout_seconds: int = 20

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')


@lru_cache
def get_settings() -> Settings:
    return Settings()
