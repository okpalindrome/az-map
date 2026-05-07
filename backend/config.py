from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "az-map"
    db_path: str = str(Path.home() / ".az-map" / "azmap.db")
    snapshots_dir: str = str(Path.home() / ".az-map" / "snapshots")
    graph_api_base: str = "https://graph.microsoft.com/v1.0"
    arm_api_base: str = "https://management.azure.com"
    # Timeout in seconds for API calls
    api_timeout: int = 30
    # Max concurrent API requests per collector
    max_concurrency: int = 10

    class Config:
        env_prefix = "AZMAP_"


settings = Settings()

# Ensure data directories exist
Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
Path(settings.snapshots_dir).mkdir(parents=True, exist_ok=True)
