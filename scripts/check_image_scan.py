"""Fail closed on high/critical image findings and report remediation metadata."""
import json
import sys
from pathlib import Path


def main(path: Path) -> int:
    report = json.loads(path.read_text(encoding="utf-8"))
    matches = report["matches"]
    if not isinstance(matches, list):
        raise ValueError("scanner matches missing")
    failed = False
    for row in matches:
        vulnerability, package = row["vulnerability"], row["artifact"]
        severity = vulnerability["severity"].lower()
        if severity not in {"high", "critical"}:
            continue
        fix = vulnerability["fix"]
        print(json.dumps({"severity": severity, "id": vulnerability["id"], "package": package["name"],
                          "version": package["version"], "type": package["type"], "fix": fix["state"],
                          "versions": fix["versions"]}, ensure_ascii=True))
        failed = True
    if failed:
        print("High or critical image findings block candidate packaging.", file=sys.stderr)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
