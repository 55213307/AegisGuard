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

    # Wazuh alert ingestion. The manager writes alerts here (owner wazuh:wazuh,
    # mode 640) — the service user must be in the wazuh group to read it. The
    # ingester idles when the file doesn't exist (e.g. local dev on Windows).
    ingest_enabled: bool = True
    alerts_file_path: str = "/var/ossec/logs/alerts/alerts.json"
    ingest_poll_seconds: float = 5.0

    # Behavioral anomaly model (app/services/ml/registry.py): one Isolation
    # Forest per endpoint, trained at start-up and then retrained on a schedule
    # so it keeps following the user's behavior.
    ml_enabled: bool = True
    ml_retrain_days: float = 7.0
    ml_start_delay_seconds: float = 15.0
    # Real events older than this don't shape the baseline.
    ml_window_days: int = 90
    # The first baseline: a dataset file made by ml/seed_baseline.py --out,
    # trained on for an endpoint (the file's endpoint_id) until it has enough
    # real history. Empty = none. Relative to the backend directory.
    ml_baseline_csv: str = ""
    # Or a directory with one dataset per endpoint, endpoint-<id>.csv.gz (made
    # with seed_baseline.py --out), for when several computers have their own.
    ml_baseline_dir: str = ""
    # An endpoint with no dataset file gets a baseline built automatically (see
    # ml/baseline.py) for this working pattern: "day" (09:00-18:00) or "night"
    # (22:00-06:00). Turn off to train only on files and real history.
    ml_auto_baseline: bool = True
    ml_default_shift: str = "day"
    # How often to look for endpoints that don't have a model yet (new ones).
    ml_check_minutes: float = 5.0
    # Until an endpoint has this much real history the baseline file is
    # trained on together with whatever real events exist; after it, real only.
    ml_min_real_actions: int = 2000
    ml_min_real_days: int = 14
    # Leave out real events the current model already flags as anomalous, so
    # an attack never becomes part of "normal".
    ml_exclude_flagged: bool = True


settings = Settings()
