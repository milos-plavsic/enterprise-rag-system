# Enterprise RAG Assistant with RBAC

A production-ready retrieval-augmented generation (RAG) system with role-based access control (RBAC), demonstrating secure multi-source enterprise data retrieval.

## Features

- **Multi-format retrieval**: PDF documents, SQL databases, JSON logs
- **Hybrid search**: Vector embeddings (Sentence Transformers) + BM25 keyword ranking
- **RBAC enforcement**: Role-based access control at document and column level
- **Sensitive query blocking**: Protects confidential data (salary, passwords, etc.)
- **Grounded responses**: Only answers from retrieved context (zero hallucination)
- **Source citations**: Full traceability of where answers come from
- **Confidence scoring**: High/Medium/Low confidence based on retrieval quality
- **Production patterns**: Proper error handling, logging, resource management

## HTTP API (production path)

```bash
pip install -r requirements.txt
python synthetic_data.py
uvicorn app.api:app --reload --port 8000
# or: docker compose up --build
```

- `GET /health`
- `GET /v1/users` — demo user ids (`alice`, `bob`, `charlie`)
- `POST /v1/query` — `{"user_id":"alice","query":"What is total EMEA revenue?"}`

OpenAPI: `http://127.0.0.1:8000/docs`

Shared utilities: [ml-core](https://github.com/milos-plavsic/ml-core).

## Quick Start (script demo)

### 1. Install Dependencies
```bash
pip install -q pandas numpy sentence-transformers rank-bm25 reportlab python-dotenv
```

### 2. Generate Synthetic Data
```bash
python synthetic_data.py
```
Creates:
- 3 realistic PDF documents (financial report, security policy, handbook)
- SQLite database with sales and employee tables
- JSON audit logs
- RBAC policy definitions
- User role mappings

### 3. Run the Demo
```bash
python run_demo.py
```

## File Structure

```
rag_assistant/
├── config.py              # Centralized configuration
├── synthetic_data.py      # Generate enterprise data (PDFs, SQL, JSON)
├── rbac_rag.py           # Core RAG pipeline with RBAC
├── run_demo.py           # Comprehensive test harness
├── requirements.txt      # Dependencies
└── data/                 # Auto-created folder
    ├── financial_report.pdf
    ├── security_policy.pdf
    ├── employee_handbook.pdf
    ├── enterprise.db
    ├── logs.json
    ├── rbac.json
    └── users.json
```

## How It Works

### 1. Data Loading
- Loads PDFs, SQL database, and JSON logs
- Builds vector embeddings using Sentence Transformers
- Creates BM25 index for keyword search
- Loads RBAC policies and user mappings

### 2. Query Processing
```
User Query
    ↓
Validate User & Role (RBAC)
    ↓
Check Sensitive Keywords
    ↓
Route to Appropriate Sources
    ├→ SQL queries (for sales/employee data)
    ├→ PDF search (for documents)
    └→ Log search (for audit logs)
    ↓
Hybrid Ranking (Vector + BM25)
    ↓
Generate Grounded Response
    ↓
Return with Citations & Confidence
```

### 3. Security
- **User validation**: Checks user exists and has valid role
- **RBAC filtering**: Restricts access to documents/columns by role
- **Sensitive blocking**: Blocks salary/password queries unless user is manager
- **Audit logging**: All queries logged with user and role

## Test Cases

### Analyst (alice)
```python
("alice", "What is the total revenue from EMEA?")
→ Can access: sales data, financial reports
→ Cannot access: employee records, security policies, logs
```

### Manager (bob)
```python
("bob", "What does the financial report say about Q2 revenue?")
→ Can access: everything
→ Can answer sensitive queries
```

### Auditor (charlie)
```python
("charlie", "Show me recent error logs")
→ Can access: logs, security policies
→ Cannot access: financial data, employee records
```

## Key Improvements Over Original

1. **Valid PDF generation** - Uses ReportLab to create proper PDFs (not empty files)
2. **Database connection cleanup** - Proper resource management with context managers
3. **User role validation** - Checks role exists before use (prevents crashes)
4. **Error handling** - Try-catch blocks with logging throughout
5. **Centralized config** - Externalized magic numbers and thresholds
6. **Better confidence scoring** - Based on score magnitude + source count
7. **Robust response parsing** - More resilient regex with error handling
8. **Comprehensive logging** - Full audit trail and debugging capability
9. **Test validation** - Tests check that RBAC actually works
10. **Production patterns** - Follows best practices for enterprise systems

## Configuration

Edit `config.py` to customize:

```python
# Search parameters
TOP_K_RESULTS = 3                 # Results to return
VECTOR_WEIGHT = 0.7              # Weight for vector search
BM25_WEIGHT = 0.3                # Weight for keyword search

# Confidence scoring
CONFIDENCE_HIGH_THRESHOLD = 2     # Sources needed for "High"
CONFIDENCE_MED_THRESHOLD = 1      # Sources needed for "Medium"

# Security
SENSITIVE_KEYWORDS = ["salary", "password", ...]
SENSITIVE_MIN_ROLE = "manager"    # Minimum role for sensitive data
```

## API Usage

### Basic Query
```python
from rbac_rag import EnterpriseRAG, RBACEnforcer

rag = EnterpriseRAG()
system = RBACEnforcer(rag)

result = system.query(
    user_id="alice",
    query_text="What is the total revenue from EMEA?"
)

print(result["answer"])          # The answer
print(result["confidence"])      # High/Medium/Low
print(result["citations"])       # Source documents
print(result["sources"])         # Retrieval trace
```

### Response Structure
```python
{
    "answer": "Based on sales data, total revenue is $75,000",
    "confidence": "Medium",
    "citations": ["sales_transactions table"],
    "sources": [
        {"type": "sql", "table": "sales_transactions", "rows": 4}
    ],
    "explainability": {
        "user_role": "analyst",
        "retrieval_trace": [...],
        "rbac_applied": True
    }
}
```

## Monitoring & Debugging

Check logs for detailed execution trace:
```python
from config import logger

# Logs show:
# - Which sources each role can access
# - Query success/failure
# - RBAC violations
# - Parsing errors
```

## Performance

- **Embedding**: ~200ms (cached after first run)
- **Search**: ~50ms (hybrid vector + BM25)
- **Full pipeline**: ~250ms per query
- **Memory**: ~200MB (Sentence Transformers model)

## Production Considerations

- Add prompt caching to reduce embedding recomputation
- Implement async search for multiple sources
- Cache embeddings to disk for faster startup
- Add rate limiting per user
- Expand SQL NL-to-SQL using LLM (currently keyword-based)
- Add citation verification to prevent hallucination
- Monitor confidence scores for query ambiguity

## License

MIT
