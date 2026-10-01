from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    demo_mode: bool = True
    ai_api_key: str = ""
    ai_api_base_url: str = "https://api.openai.com/v1"
    ai_model: str = ""
    ai_request_timeout_seconds: float = Field(default=60, gt=0, le=300)
    frontend_url: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


settings = Settings()

VERCEL_FRONTEND_ORIGINS = [
    "https://scamshield-ai-j7gz.vercel.app",
    "https://scamshield-ai-j7gz-ed4qkl7s-tarunkataria007s-projects.vercel.app",
]
LOCAL_FRONTEND_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def get_cors_origins() -> list[str]:
    """Allow the deployed ScamShield frontends, local Vite, and configured extra origins."""
    configured = [
        origin.strip().rstrip("/")
        for origin in settings.frontend_url.split(",")
        if origin.strip() and origin.strip() != "*"
    ]
    return list(dict.fromkeys([*VERCEL_FRONTEND_ORIGINS, *LOCAL_FRONTEND_ORIGINS, *configured]))
