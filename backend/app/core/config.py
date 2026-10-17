import os
from dotenv import load_dotenv  # Add this import

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application settings loaded from environment variables."""
    
    # Project metadata
    PROJECT_NAME: str = "Compliance Platform API"
    VERSION: str = "1.0.0"
    
    # Security
    SECRET_KEY: str = os.getenv("JWT_SECRET", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://compliance_user:compliance_sec@localhost/compliance_db")
    
    def __init__(self):
        """Validate required settings on initialization."""
        if not self.SECRET_KEY:
            raise ValueError(
                "JWT_SECRET_KEY environment variable is required. "
                "Please set it before starting the application."
            )
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return os.getenv("ENVIRONMENT", "development") == "production"


# Global settings instance
settings = Settings()
