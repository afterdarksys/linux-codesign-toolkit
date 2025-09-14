"""
Configuration settings for the Code Signing API.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application configuration settings."""

    # API Configuration
    api_title: str = "Linux Code Signing Toolkit API"
    api_description: str = "Modern API-driven code signing toolkit for Windows, Java, AIR, and Apple packages"
    api_version: str = "2.0.0"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False

    # Security
    secret_key: str = "your-super-secret-key-change-this-in-production"
    access_token_expire_minutes: int = 30
    algorithm: str = "HS256"

    # Database
    database_url: str = "sqlite+aiosqlite:///./codesign_api.db"

    # File Storage
    upload_directory: str = "./uploads"
    max_file_size: int = 500 * 1024 * 1024  # 500MB
    allowed_extensions: List[str] = [
        # Windows
        ".exe", ".dll", ".sys", ".msi", ".cab", ".cat", ".appx", ".msix",
        # Java
        ".jar", ".war", ".ear",
        # AIR
        ".air",
        # Apple
        ".pkg", ".ipa", ".app", ".dmg"
    ]

    # Signing Configuration
    osslsigncode_path: str = "osslsigncode"
    jarsigner_path: str = "jarsigner"
    keytool_path: str = "keytool"
    codesign_path: str = "codesign"  # Apple codesign
    isign_path: str = "isign"  # iOS signing on Linux

    # Certificate Storage
    certificate_directory: str = "./certificates"
    keystore_directory: str = "./keystores"

    # Default URLs
    default_timestamp_url: str = "http://timestamp.digicert.com"

    # Rate Limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # JIRA Integration (optional)
    jira_url: Optional[str] = None
    jira_username: Optional[str] = None
    jira_token: Optional[str] = None
    jira_project: Optional[str] = None

    # Download Links
    base_download_url: str = "http://localhost:8000/api/v1/download"
    download_link_expiry_hours: int = 24

    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

# Create necessary directories
os.makedirs(settings.upload_directory, exist_ok=True)
os.makedirs(settings.certificate_directory, exist_ok=True)
os.makedirs(settings.keystore_directory, exist_ok=True)