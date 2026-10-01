from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480

    # Frontend build lives one level up, in AegisGuard/admin/frontend.
    frontend_dir: str = "../frontend"

    # Base URL of the company portal (AegisGuard/company/backend), used to
    # build each company's own login link.
    company_portal_url: str = "http://localhost:8002"


settings = Settings()
