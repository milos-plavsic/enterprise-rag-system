"""Configuration for Enterprise RAG System"""
import logging
from pathlib import Path

# Paths
DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "enterprise.db"
RBAC_PATH = DATA_DIR / "rbac.json"
USERS_PATH = DATA_DIR / "users.json"
LOGS_PATH = DATA_DIR / "logs.json"

# Model
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# Search
TOP_K_RESULTS = 3
VECTOR_WEIGHT = 0.7
BM25_WEIGHT = 0.3
MIN_RELEVANCE_SCORE = 0.1

# Confidence thresholds
CONFIDENCE_HIGH_THRESHOLD = 2  # Sources needed for "High"
CONFIDENCE_MED_THRESHOLD = 1   # Sources needed for "Medium"

# Sensitive keywords that require elevated permissions
SENSITIVE_KEYWORDS = ["salary", "password", "confidential", "secret", "ssn", "credit"]
SENSITIVE_MIN_ROLE = "manager"  # Only manager and above can access sensitive

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
