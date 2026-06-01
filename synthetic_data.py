"""Generate synthetic enterprise data for RAG system"""
import json
import sqlite3
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import logging

from config import DATA_DIR, DB_PATH, RBAC_PATH, USERS_PATH, LOGS_PATH, logger

DATA_DIR.mkdir(exist_ok=True)

# 1. Generate PDFs using ReportLab (creates valid PDFs)
def create_pdf(filename, title, content):
    """Create a valid PDF file with content"""
    try:
        pdf_path = DATA_DIR / filename
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        c.setTitle(title)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, 750, title)
        c.setFont("Helvetica", 11)
        y = 720
        for line in content.split('\n'):
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(50, y, line)
            y -= 20
        c.save()
        logger.info(f"✅ Created {filename}")
    except Exception as e:
        logger.error(f"❌ Failed to create {filename}: {e}")
        raise

pdf_docs = {
    "financial_report.pdf": ("Q2 2024 Financial Report",
        "Enterprise Financial Report Q2 2024\n\n"
        "Total Revenue: $5.2M\n"
        "EMEA Region: $2.1M (40%)\n"
        "North America: $2.0M (38%)\n"
        "APAC Region: $1.1M (22%)\n\n"
        "Customer Breakdown:\n"
        "Gold Tier: $1.8M\n"
        "Platinum Tier: $2.1M\n"
        "Silver Tier: $1.3M\n\n"
        "Key Accounts: Acme Corp ($50K), TechCorp ($75K), Beta Inc ($25K)"),
    "security_policy.pdf": ("Security Access Policy",
        "Enterprise Security Policy\n\n"
        "Access Control:\n"
        "- Financial data requires Manager role minimum\n"
        "- Audit logs restricted to Auditor role\n"
        "- Employee records require Manager approval\n\n"
        "Incident Response:\n"
        "- All unauthorized access attempts logged\n"
        "- Manager notified within 1 hour\n"
        "- Audit trail maintained for 90 days\n\n"
        "Data Classification:\n"
        "- Public: All documents\n"
        "- Internal: Financial, Employee data\n"
        "- Confidential: Salary, Security configs"),
    "employee_handbook.pdf": ("Employee Handbook",
        "Enterprise Employee Handbook 2024\n\n"
        "Time Off Policy:\n"
        "- All employees receive 20 PTO days annually\n"
        "- Unused PTO does not carry over\n"
        "- Managers must approve requests\n\n"
        "HR Contact:\n"
        "- Email: peopleops@company.com\n"
        "- Phone: ext. 5000\n"
        "- Hours: 9 AM - 5 PM EST\n\n"
        "Benefits:\n"
        "- Health insurance (medical, dental, vision)\n"
        "- 401(k) with 4% company match")
}

for filename, (title, content) in pdf_docs.items():
    create_pdf(filename, title, content)

# 2. Generate SQLite database
try:
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sales_transactions (
        transaction_id INTEGER PRIMARY KEY,
        region TEXT,
        amount INTEGER,
        customer_tier TEXT,
        customer_name TEXT
    )
    """)

    sales_data = [
        (101, "EMEA", 50000, "Gold", "Acme Corp"),
        (102, "NA", 75000, "Platinum", "TechCorp"),
        (103, "EMEA", 25000, "Silver", "Beta Inc"),
        (104, "APAC", 30000, "Gold", "Gamma Ltd"),
        (105, "NA", 45000, "Gold", "Delta Systems"),
    ]
    cursor.executemany("INSERT OR IGNORE INTO sales_transactions VALUES (?,?,?,?,?)", sales_data)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        emp_id INTEGER PRIMARY KEY,
        name TEXT,
        department TEXT,
        clearance_level INTEGER
    )
    """)

    employees = [
        (1, "Alice Johnson", "Sales", 2),
        (2, "Bob Smith", "Finance", 3),
        (3, "Charlie Brown", "Audit", 1),
    ]
    cursor.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?,?)", employees)

    conn.commit()
    conn.close()
    logger.info("✅ Created enterprise.db")
except Exception as e:
    logger.error(f"❌ Failed to create database: {e}")
    raise

# 3. Generate JSON logs
logs = [
    {"timestamp": "2025-04-01T10:00:00Z", "service": "api", "level": "ERROR", "msg": "Rate limit exceeded for user alice"},
    {"timestamp": "2025-04-01T10:05:00Z", "service": "db", "level": "WARN", "msg": "Slow query detected in sales_transactions"},
    {"timestamp": "2025-04-01T10:10:00Z", "service": "auth", "level": "INFO", "msg": "User bob authenticated successfully"},
    {"timestamp": "2025-04-01T10:15:00Z", "service": "api", "level": "ERROR", "msg": "Connection timeout to external service"},
]
try:
    with open(LOGS_PATH, "w") as f:
        json.dump(logs, f, indent=2)
    logger.info("✅ Created logs.json")
except Exception as e:
    logger.error(f"❌ Failed to create logs: {e}")
    raise

# 4. RBAC Policies
rbac_policies = {
    "roles": {
        "analyst": {
            "allowed_sources": ["sales_transactions", "financial_report.pdf"],
            "mask_columns": ["customer_name"]
        },
        "manager": {
            "allowed_sources": ["sales_transactions", "financial_report.pdf", "employees", "employee_handbook.pdf"],
            "mask_columns": []
        },
        "auditor": {
            "allowed_sources": ["logs.json", "security_policy.pdf"],
            "mask_columns": []
        }
    },
    "documents": {
        "financial_report.pdf": ["analyst", "manager"],
        "security_policy.pdf": ["auditor", "manager"],
        "employee_handbook.pdf": ["manager"]
    }
}
try:
    with open(RBAC_PATH, "w") as f:
        json.dump(rbac_policies, f, indent=2)
    logger.info("✅ Created rbac.json")
except Exception as e:
    logger.error(f"❌ Failed to create RBAC policies: {e}")
    raise

# 5. User mappings
users = {
    "alice": {"role": "analyst"},
    "bob": {"role": "manager"},
    "charlie": {"role": "auditor"}
}
try:
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=2)
    logger.info("✅ Created users.json")
except Exception as e:
    logger.error(f"❌ Failed to create user mappings: {e}")
    raise

print("\n" + "="*60)
print("✅ Synthetic data generated successfully!")
print("="*60)
