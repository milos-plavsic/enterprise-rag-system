"""Original, fictional policy corpus. No customer or third-party records."""
import hashlib
import json
import sys
from pathlib import Path

# key, display title, corpus paragraph, roles
POLICIES = (
    ("travel-expenses", "Travel reimbursements", "Expense reimbursement requires manager approval when a single expense exceeds 250 credits. Receipts are required for expenses above 30 credits.", ("analyst", "manager")),
    ("annual-leave", "Annual leave", "Vacation leave requests should be submitted ten business days before departure. Each employee has twenty leave days per year.", ("analyst", "manager")),
    ("credential-policy", "Credential renewal", "Privileged credentials must be renewed after suspected exposure. The security desk coordinates the password reset.", ("auditor", "manager")),
    ("records-retention", "Records retention", "Procurement records must be archived for seven years. Retention runs from the contract closure date.", ("auditor", "manager")),
    ("office-supplies", "Office supplies", "Office supply orders are consolidated every Tuesday. Use the stockroom form to request notebooks and pens.", ("analyst", "manager", "auditor")),
    ("shipping-labels", "Shipping labels", "Use teal labels for outbound parcels and amber labels for returned items. The shipping room closes at sixteen hundred.", ("analyst", "manager", "auditor")),
    ("operations", "Facilities runbook", "The facilities desk assigns a mailbox to each floor. Keep loading doors closed after receiving packages.", ("analyst", "manager", "auditor")),
    ("incident-notice", "Incident communications", "For a warehouse incident, notify the response coordinator by telephone. Do not include customer information in the incident notice.", ("auditor", "manager")),
)


def write(directory: Path, release: int) -> None:
    if release not in (1, 2, 3):
        raise ValueError("fixture releases are 1 (initial), 2 (updated), 3 (withdrawn)")
    directory.mkdir(exist_ok=True, parents=True)
    rows = []
    for key, title, text, roles in POLICIES:
        if key == "travel-expenses" and release == 3:
            continue
        version = 2 if key == "travel-expenses" and release == 2 else 1
        text = text.replace("250 credits", "150 credits") if version == 2 else text
        path = directory / f"{key}-v{version}.txt"
        data = (text + "\n").encode()
        if not path.exists():
            path.write_bytes(data)
            path.chmod(0o444)
        elif path.read_bytes() != data:
            raise ValueError("existing version differs from the fixture")
        rows.append({"key": key, "version": version, "title": title, "file": path.name,
                     "roles": list(roles), "effective_at": f"2026-01-0{version}T00:00:00Z",
                     "sha256": hashlib.sha256(data).hexdigest()})
    stage = directory / ".manifest.next"
    stage.write_text(json.dumps({"release": release, "documents": rows}, indent=2) + "\n", encoding="utf-8")
    stage.chmod(0o444)
    stage.replace(directory / "manifest.json")


if __name__ == "__main__":
    write(Path(sys.argv[1]), int(sys.argv[2]))
