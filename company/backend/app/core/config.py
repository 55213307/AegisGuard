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

    # Wazuh Manager runs on the same server. Its API is only reachable on
    # localhost (port 55000 isn't opened in the firewall), so its self-signed
    # certificate isn't verified.
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_user: str = "wazuh"
    wazuh_api_password: str = "wazuh"
    # Address that endpoints use to reach the manager (agent port 1514).
    wazuh_manager_address: str = "192.168.241.87"
    # Must not be newer than the manager's version.
    wazuh_agent_msi_url: str = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi"

    # Portal address as reached from the endpoints (they don't have the
    # admin PC's hosts-file name), used by the screen agent to upload frames.
    portal_public_url: str = "http://192.168.241.87"


settings = Settings()
