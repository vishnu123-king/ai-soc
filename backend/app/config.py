import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-SOC Central Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Environment & Database
    # Default to sqlite locally if PostgreSQL is not configured, or use DATABASE_URL for Postgres
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{os.path.abspath(os.path.join(os.path.dirname(__file__), '../../aisoc.db'))}"
    )
    
    # Server & Ports
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("FASTAPI_PORT", "8088"))
    
    # Authentication & JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "aisoc-insecure-development-secret-key-change-in-production-987654321")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # AI Providers Configuration
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    LOCAL_LLM_BASE_URL: str = os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:11434/v1")
    LOCAL_LLM_MODEL: str = os.getenv("LOCAL_LLM_MODEL", "qwen2.5:7b")
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    
    # Agent Registration
    DEFAULT_AGENT_SHARED_KEY: str = os.getenv("AGENT_ENROLLMENT_KEY", "aisoc-agent-enrollment-secret-key")

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()
