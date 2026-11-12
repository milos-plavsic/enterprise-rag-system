"""Generate synthetic fixtures only; never real or sensitive client data."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def create_pdf(name: str, title: str, lines: list[str]) -> None:
    c = canvas.Canvas(str(DATA_DIR/name), pagesize=letter)
    c.setTitle(title)
    c.setFont("Helvetica-Bold",14)
    c.drawString(45,750,title)
    c.setFont("Helvetica",11)
    y=720
    for line in lines:
        if y<60:
            c.showPage()
            y=750
            c.setFont("Helvetica",11)
        c.drawString(45,y,line)
        y-=18
    c.save()

create_pdf("financial_report.pdf","Q2 2024 Financial Report",[
    "Enterprise Financial Report Q2 2024", "Total Revenue: $5.2M",
    "EMEA Region: $2.1M", "North America: $2.0M", "APAC Region: $1.1M",
    "Figures cover a reporting period distinct from the sample transaction dataset."
])
create_pdf("security_policy.pdf","Security Access Policy",[
    "Internal Security Policy", "Security records require the auditor role.",
    "Document access must be determined by authenticated role.",
    "All human users are required to follow access controls."
])
create_pdf("employee_handbook.pdf","Employee Handbook",[
    "Employee Handbook", "Employees receive 20 PTO days annually.",
    "Benefits include health insurance and a 401k retirement plan.",
])
with sqlite3.connect(DATA_DIR/"enterprise.db") as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS sales_transactions(
      transaction_id INTEGER PRIMARY KEY, region TEXT NOT NULL, amount INTEGER NOT NULL,
      customer_tier TEXT NOT NULL, customer_name TEXT NOT NULL)""")
    conn.executemany(
        "INSERT OR IGNORE INTO sales_transactions VALUES (?,?,?,?,?)",
        [
            (101,"EMEA",50000,"Gold","Acme Corp"),
            (102,"NA",75000,"Platinum","TechCorp"),
            (103,"EMEA",25000,"Silver","Beta Inc"),
            (104,"APAC",30000,"Gold","Gamma Ltd"),
            (105,"NA",45000,"Gold","Delta Systems"),
        ],
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS employees(
      emp_id INTEGER PRIMARY KEY,name TEXT NOT NULL,department TEXT NOT NULL,
      clearance_level INTEGER NOT NULL)""")
    conn.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?,?)",[
      (1,"Alice Johnson","Sales",2),(2,"Bob Smith","Finance",3),(3,"Charlie Brown","Audit",1)
    ])
logs=[
    {"timestamp":"2025-04-01T10:00:00Z","level":"ERROR","msg":"Rate limit exceeded"},
    {"timestamp":"2025-04-01T10:05:00Z","level":"WARN","msg":"Slow query detected"},
    {"timestamp":"2025-04-01T10:10:00Z","level":"INFO","msg":"User authenticated"},
    {"timestamp":"2025-04-01T10:15:00Z","level":"ERROR","msg":"External service timeout"},
]
(DATA_DIR/"logs.json").write_text(json.dumps(logs,indent=2)+"\n",encoding="utf-8")
policy={
 "roles":{
    "analyst":{"allowed_sources":["sales_transactions","financial_report.pdf"]},
    "manager":{"allowed_sources":["sales_transactions","financial_report.pdf","security_policy.pdf","employee_handbook.pdf","employees","uploads"]},
    "auditor":{"allowed_sources":["logs.json","security_policy.pdf"]},
 },
 "documents":{
    "financial_report.pdf":["analyst","manager"],
    "security_policy.pdf":["auditor","manager"],
    "employee_handbook.pdf":["manager"],
 },
}
(DATA_DIR/"rbac.json").write_text(json.dumps(policy,indent=2)+"\n",encoding="utf-8")
print("Synthetic fixtures generated successfully")
