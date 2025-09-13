# src/config.py
"""Configuration management for Red Team Scenario Generator."""

import os
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Centralized configuration management."""
    
    # Database settings
    VECTOR_DB_PATH: str = os.getenv("VECTOR_DB_PATH", "./chroma_db")
    COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "redteam_scenarios")
    
    # Embedding model settings
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    # Alternative: "all-mpnet-base-v2" for better quality, slower speed
    
    # API settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-sonnet-20240229")
    
    # Query settings
    DEFAULT_N_RESULTS: int = int(os.getenv("DEFAULT_N_RESULTS", "5"))
    MAX_N_RESULTS: int = int(os.getenv("MAX_N_RESULTS", "20"))
    SIMILARITY_THRESHOLD: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.7"))
    
    # Data loading settings
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "100"))
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    
    # Logging settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/app.log")
    LOG_FORMAT: str = os.getenv(
        "LOG_FORMAT", 
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # MITRE ATT&CK settings
    MITRE_DOMAIN: str = os.getenv("MITRE_DOMAIN", "enterprise-attack")
    INCLUDE_DEPRECATED: bool = os.getenv("INCLUDE_DEPRECATED", "false").lower() == "true"
    
    # Evaluation settings
    EVALUATION_CRITERIA: List[str] = [
        "level_of_detail",
        "technical_accuracy", 
        "realism",
        "creativity",
        "understandability"
    ]
    EVALUATION_SCALE_MAX: int = 10
    EVALUATION_SCALE_MIN: int = 1
    
    # Scenario generation settings
    MAX_PROMPT_LENGTH: int = int(os.getenv("MAX_PROMPT_LENGTH", "4000"))
    INCLUDE_EXAMPLES: bool = os.getenv("INCLUDE_EXAMPLES", "true").lower() == "true"
    
    @classmethod
    def validate(cls) -> List[str]:
        """Validate configuration and return any issues."""
        issues = []
        
        # Check required API keys
        if not cls.OPENAI_API_KEY and not cls.ANTHROPIC_API_KEY:
            issues.append("No LLM API key configured (OPENAI_API_KEY or ANTHROPIC_API_KEY)")
        
        # Check numeric ranges
        if cls.DEFAULT_N_RESULTS > cls.MAX_N_RESULTS:
            issues.append("DEFAULT_N_RESULTS cannot be greater than MAX_N_RESULTS")
        
        if not (0.0 <= cls.SIMILARITY_THRESHOLD <= 1.0):
            issues.append("SIMILARITY_THRESHOLD must be between 0.0 and 1.0")
        
        # Check paths
        if not os.path.exists(os.path.dirname(cls.LOG_FILE)):
            os.makedirs(os.path.dirname(cls.LOG_FILE), exist_ok=True)
        
        return issues
    
    @classmethod
    def get_llm_config(cls) -> dict:
        """Get LLM configuration based on available API keys."""
        if cls.OPENAI_API_KEY:
            return {
                "provider": "openai",
                "api_key": cls.OPENAI_API_KEY,
                "model": cls.OPENAI_MODEL,
                "max_tokens": 2000,
                "temperature": 0.7
            }
        elif cls.ANTHROPIC_API_KEY:
            return {
                "provider": "anthropic",
                "api_key": cls.ANTHROPIC_API_KEY,
                "model": cls.ANTHROPIC_MODEL,
                "max_tokens": 2000,
                "temperature": 0.7
            }
        else:
            raise ValueError("No LLM API key configured")

# Create global config instance
config = Config()

# Validate configuration on import
validation_issues = config.validate()
if validation_issues:
    import warnings
    for issue in validation_issues:
        warnings.warn(f"Configuration issue: {issue}")