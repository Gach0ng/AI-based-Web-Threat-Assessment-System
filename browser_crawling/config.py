"""Configuration for browser crawling"""
from dataclasses import dataclass


@dataclass
class Config:
    """Browser crawling configuration"""
    timeout_ms: int = 30000
    retry_times: int = 2
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    viewport_width: int = 1920
    viewport_height: int = 1080
    headless: bool = True
    disable_images: bool = False