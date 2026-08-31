"""
Configuration module for IntelAssist AI.
Manages application constants, default parameters, data directories, and environment settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DOCS_DIR = DATA_DIR / "documents"
LOGS_DIR = DATA_DIR / "logs"
INVESTIGATIONS_DIR = DATA_DIR / "investigations"
USERS_DIR = DATA_DIR / "users"
VECTOR_DB_DIR = DATA_DIR / "vector_db"
CONVERSATIONS_DIR = DATA_DIR / "conversations"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

# Ensure all directories exist
for directory in [
    DATA_DIR, UPLOAD_DIR, DOCS_DIR, LOGS_DIR,
    INVESTIGATIONS_DIR, USERS_DIR, VECTOR_DB_DIR,
    CONVERSATIONS_DIR, SAMPLE_DATA_DIR
]:
    directory.mkdir(parents=True, exist_ok=True)

# Application metadata
APP_NAME = "IntelAssist AI"
APP_FULL_TITLE = "IntelAssist AI — Cyber Threat Intelligence & Investigation Platform"
APP_TAGLINE = "Transforming Threat Data into Actionable Intelligence"
APP_SUBTITLE = "AI-Powered Cyber Threat Intelligence, Log Forensic Analysis & IOC Investigation"
APP_VERSION = "3.0.0 Cyber SOC Edition"
APP_AUTHOR = "Cyber Defense & Threat Intelligence Team"

# Supported file formats
SUPPORTED_EXTENSIONS = [".pdf", ".docx", ".doc", ".txt", ".md", ".csv", ".json", ".log"]
MAX_FILE_SIZE_MB = 50

# Default RAG & Chunking Parameters
DEFAULT_CHUNK_SIZE = 500
DEFAULT_CHUNK_OVERLAP = 100
DEFAULT_TOP_K = 6
DEFAULT_SIMILARITY_THRESHOLD = 0.15

# LLM Providers and Models
DEFAULT_LLM_PROVIDER = os.getenv("DEFAULT_LLM_PROVIDER", "Demo Mode (Smart AI)")
AVAILABLE_PROVIDERS = [
    "Demo Mode (Smart AI)",
    "Google Gemini",
    "NVIDIA NIM / AI",
    "OpenAI"
]

AVAILABLE_GEMINI_MODELS = [
    "gemini-flash-latest",
    "gemini-pro-latest",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
]

AVAILABLE_NVIDIA_MODELS = [
    "meta/llama-3.2-11b-vision-instruct",
    "deepseek-ai/deepseek-coder-6.7b-instruct",
    "mistralai/mistral-large-2-instruct",
    "nvidia/nemotron-4-340b-instruct",
]

AVAILABLE_OPENAI_MODELS = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-3.5-turbo",
]

DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_TOKENS = 2048

# API Keys from environment (Securely loaded via .env)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

