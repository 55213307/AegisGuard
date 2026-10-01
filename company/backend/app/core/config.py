from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Same PostgreSQL database as the admin backend: company logins live on
    # the admin-owned `accounts` table.
    database_url: str
    # Must differ from the admin backend's key so an admin token can never be
    # accepted by the company portal (and vice versa).
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480

    frontend_dir: str = "../frontend"


settings = Settings()
