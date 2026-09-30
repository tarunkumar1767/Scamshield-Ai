from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    demo_mode: bool = True
    ai_api_key: str = ""
    ai_api_base_url: str = "https://api.openai.com/v1"
    ai_model: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


settings = Settings()
