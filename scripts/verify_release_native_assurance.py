"""Bind final VEX/decisions to the approved effective runtime filesystem.

Run after the image identity, native image review, two vulnerability scans and
the product-specific disposition evaluator. This is a tamper-evident acceptance
gate, not an independent review or a claim of formal dynamic reachability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

if __package__:
    from .native_archive_inventory import consumer_paths, digest
else:
    from native_archive_inventory import consumer_paths, digest

SHA256 = re.compile(r"sha256:[a-f0-9]{64}\Z")
FIELDS = (
    "elf_count", "elf_inventory_sha256", "python_source_count",
    "python_inventory_sha256", "application_source_sha256", "direct_consumers",
    "effective_filesystem_entries", "effective_filesystem_sha256",
)


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError("native release assurance: " + label)


def verify(native: dict, baseline: dict, identity: dict, decisions: dict, vex: dict) -> dict:
    require(all(isinstance(x, dict) for x in (native, baseline, identity, decisions, vex)),
            "invalid input document")
    require(native.get("schema") == 1 and native.get("accepted") is True, "native gate did not accept")
    require(baseline.get("schema") == 1, "unsupported native baseline schema")
    require(isinstance(native.get("baseline_sha256"), str)
            and native["baseline_sha256"] == digest(baseline), "review baseline content mismatch")
    for nkey, ikey in (("image_manifest_digest", "manifest_digest"),
                       ("archive_sha256", "archive_sha256")):
        require(isinstance(identity.get(ikey), str) and SHA256.fullmatch(identity[ikey])
                and native.get(nkey) == identity[ikey], nkey + " differs from candidate")
    observed = native.get("observed")
    require(isinstance(observed, dict), "observed inventory missing")
    for field in FIELDS:
        require(field in baseline and observed.get(field) == baseline[field],
                "unreviewed baseline field: " + field)
    require(observed.get("application_source_sha256") == identity.get("source_tree_sha256"),
            "application source identity mismatch")
    fs = native.get("effective_filesystem")
    require(isinstance(fs, dict) and len(fs) == observed["effective_filesystem_entries"]
            and digest(fs) == observed["effective_filesystem_sha256"],
            "effective filesystem contents differ from inventory receipt")
    for name, entry in fs.items():
        require(isinstance(name, str) and isinstance(entry, (list, tuple))
                and len(entry) == 5 and entry[0] in {"file", "directory", "symlink", "hardlink"}
                and isinstance(entry[2], int) and isinstance(entry[3], int)
                and isinstance(entry[4], int), "malformed effective filesystem entry")
        if entry[0] == "file":
            require(isinstance(entry[1], str) and re.fullmatch(r"[a-f0-9]{64}", entry[1]) is not None,
                    "invalid filesystem content hash")
        if entry[0] in {"symlink", "hardlink"}:
            require(isinstance(entry[1], str), "invalid runtime link target")
    elf = native.get("elf")
    sources = native.get("python_sources")
    require(isinstance(elf, dict) and isinstance(sources, dict), "ELF or source inventory missing")
    require(len(elf) == observed["elf_count"] and
            digest({p: v["sha256"] for p, v in elf.items()}) == observed["elf_inventory_sha256"],
            "ELF inventory digest differs")
    require(len(sources) == observed["python_source_count"] and
            digest(sources) == observed["python_inventory_sha256"], "Python source inventory differs")
    direct, transitive = consumer_paths(elf)
    require(direct == observed["direct_consumers"]
            and transitive == observed.get("transitive_consumers"), "native linkage graph differs")
    require(decisions.get("schema") == 1
            and decisions.get("image_manifest_digest") == identity["manifest_digest"]
            and decisions.get("image_config_digest") == identity.get("config_digest"),
            "release decisions and image identity differ")
    require(decisions.get("unresolved") == [], "unresolved release findings")
    require(isinstance(decisions.get("resolved"), list), "release resolution evidence missing")
    statements = vex.get("statements")
    require(isinstance(statements, list) and statements, "release VEX statements missing")
    require(all(isinstance(item, dict) and item.get("status") == "not_affected"
                and isinstance(item.get("products"), list) and item["products"]
                and all(isinstance(prod, dict) and
                        prod.get("hashes", {}).get("sha-256") == identity["manifest_digest"][7:]
                        for prod in item["products"])
                for item in statements), "VEX product identity or status mismatch")
    return {
        "schema": 1,
        "accepted": True,
        "source_commit": identity["source_commit"],
        "manifest_digest": identity["manifest_digest"],
        "archive_sha256": identity["archive_sha256"],
        "reviewed_baseline_sha256": native["baseline_sha256"],
        "effective_filesystem_sha256": observed["effective_filesystem_sha256"],
        "effective_filesystem_entries": observed["effective_filesystem_entries"],
        "resolved_count": len(decisions["resolved"]),
        "vex_statements": len(statements),
        "qualification": "Exact-image drift/disposition binding, not independent security approval.",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "baseline", "identity", "decisions", "vex", "output"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    data = [json.loads(getattr(args, name).read_bytes())
            for name in ("native", "baseline", "identity", "decisions", "vex")]
    result = verify(*data)
    for name in ("native", "baseline", "identity", "decisions", "vex"):
        content = getattr(args, name).read_bytes()
        result[name + "_sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("VERIFIED: reviewed complete runtime filesystem is bound to exact-image release dispositions")


if __name__ == "__main__":
    main()
