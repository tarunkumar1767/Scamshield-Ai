from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    demo_mode: bool = True
    ai_api_key: str = ""
    ai_api_base_url: str = "https://api.openai.com/v1"
    ai_model: str = ""
    frontend_url: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


settings = Settings()


def get_cors_origins() -> list[str]:
    """Use configured exact deployment origins, or local Vite origins for development."""
    configured = [origin.strip().rstrip("/") for origin in settings.frontend_url.split(",") if origin.strip()]
    if configured:
        return configured
    return ["http://localhost:5173", "http://127.0.0.1:5173"]
