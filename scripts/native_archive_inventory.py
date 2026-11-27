"""Inspect verified image layers without executing or extracting their contents.

This is a conservative drift detector and linkage inventory, not a proof of
dynamic reachability. The baseline must be re-reviewed independently on drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

SYSTEM_TLS = {"libssl.so.3", "libcrypto.so.3"}
PYTHON_PREFIX = "usr/local/lib/python3.12/"
MAX_FILE = 128 * 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def safe_name(name):
    name = name.removeprefix("./")
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("unsafe layer member path")
    return str(p)


def inspect_elf(data):
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(data)
        stream.flush()
        result = subprocess.run(["readelf", "-W", "-d", "--dyn-syms", stream.name],
                                capture_output=True, text=True, check=True, timeout=10)
    if result.stderr.strip():
        raise ValueError("ELF inspection produced diagnostics")
    out = result.stdout
    needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", out)
    soname = re.findall(r"\(SONAME\).*?\[(.*?)\]", out)
    if len(soname) > 1:
        raise ValueError("ambiguous ELF SONAME")
    symbols = sorted(set(re.findall(r"\bUND\s+([A-Za-z_][A-Za-z0-9_]*)", out)))
    return {"sha256": hashlib.sha256(data).hexdigest(), "needed": needed,
            "soname": soname[0] if soname else None, "undefined_symbols": symbols}


def inventory(archive):
    elf, sources, links, effective_filesystem = {}, {}, {}, {}
    def remove(path, children=False):
        for table in (elf, sources, links, effective_filesystem):
            for key in list(table):
                if key == path or children and key.startswith(path + "/"):
                    del table[key]

    with tarfile.open(archive, "r:*") as outer:
        manifests = json.load(outer.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("expected one image")
        for name in manifests[0]["Layers"]:
            with tarfile.open(fileobj=outer.extractfile(name), mode="r:*") as layer:
                members = layer.getmembers()
                # Reject ambiguous layer overrides and extended attributes,
                # including Linux file capabilities, unless they are simply
                # long-path encodings already covered by effective path/link.
                names = [safe_name(item.name) for item in members]
                if len(names) != len(set(names)):
                    raise ValueError("duplicate OCI layer entry")
                for member in members:
                    if set(member.pax_headers) - {"path", "linkpath"}:
                        raise ValueError("unreviewed OCI layer extended attributes")
                # OCI whiteouts affect lower layers, irrespective of entry order.
                for member in members:
                    path = safe_name(member.name)
                    parent, _, base = path.rpartition("/")
                    if base == ".wh..wh..opq":
                        for table in (elf, sources, links, effective_filesystem):
                            for key in list(table):
                                if key.startswith(parent + "/"):
                                    del table[key]
                    elif base.startswith(".wh."):
                        remove((parent + "/" if parent else "") + base[4:], True)
                for member in members:
                    path = safe_name(member.name)
                    if PurePosixPath(path).name.startswith(".wh."):
                        continue
                    if member.isdir():
                        effective_filesystem[path] = ("directory", None, member.mode, member.uid, member.gid)
                        continue
                    remove(path, not member.isfile())
                    metadata = (member.mode, member.uid, member.gid)
                    if member.issym():
                        links[path] = {"type": "symlink", "target": member.linkname}
                        effective_filesystem[path] = ("symlink", member.linkname, *metadata)
                    elif member.islnk():
                        target = safe_name(member.linkname)
                        links[path] = {"type": "hardlink", "target": target}
                        effective_filesystem[path] = ("hardlink", member.linkname, *metadata)
                        if target in elf:
                            elf[path] = elf[target]
                        if target in sources and path.startswith(PYTHON_PREFIX) and path.endswith(".py"):
                            sources[path] = sources[target]
                        if target not in elf and not target.startswith("usr/share/zoneinfo/") and target not in sources:
                            raise ValueError("unclassified hardlink target")
                    elif member.isfile():
                        with layer.extractfile(member) as stream:
                            magic = stream.read(4)
                            if magic == b"\x7fELF" or path.startswith(PYTHON_PREFIX) and path.endswith(".py"):
                                if member.size > MAX_FILE:
                                    raise ValueError("code file exceeds inspection limit")
                                data = magic + stream.read()
                                if len(data) != member.size:
                                    raise ValueError("incomplete file")
                                content_digest = hashlib.sha256(data).hexdigest()
                                if magic == b"\x7fELF":
                                    elf[path] = inspect_elf(data)
                                if path.startswith(PYTHON_PREFIX) and path.endswith(".py"):
                                    sources[path] = content_digest
                            else:
                                hasher = hashlib.sha256(magic)
                                for block in iter(lambda: stream.read(1024 * 1024), b""):
                                    hasher.update(block)
                                content_digest = hasher.hexdigest()
                        effective_filesystem[path] = ("file", content_digest, *metadata)
                    else:
                        raise ValueError("unexpected special layer member")
    return elf, sources, links, effective_filesystem


def consumer_paths(elf):
    direct = {path for path, row in elf.items() if SYSTEM_TLS.intersection(row["needed"])}
    reached = set(direct)
    while True:
        names = {elf[p]["soname"] for p in reached if elf[p]["soname"]}
        names.update(PurePosixPath(p).name for p in reached)
        expanded = reached | {p for p, row in elf.items() if names.intersection(row["needed"])}
        if expanded == reached:
            return sorted(direct), sorted(reached)
        reached = expanded


def normalized_filesystem(files):
    """Require the absence of unreviewed install-generated runtime artifacts.

    Dynamically generated bytecode is FORBIDDEN, not waived. The container
    uses --no-compile and PYTHONDONTWRITEBYTECODE, so Python imports its
    pinned source files. Everything else remains content-addressed.
    """
    prefix = "usr/local/lib/python3.12/site-packages/"
    generated = [name for name in files if name.startswith(prefix) and
                 (name.endswith((".pyc", ".pyo")) or name.endswith("/__pycache__"))]
    if generated:
        raise ValueError("Python install bytecode and cache directories must be absent")
    if "var/log/apk.log" in files:
        raise ValueError("unreviewed mutable APK installation log present")
    return files


def observed_baseline(elf, sources, identity, effective_filesystem):
    direct, _ = consumer_paths(elf)
    effective = normalized_filesystem(effective_filesystem)
    return {"elf_count": len(elf),
            "elf_inventory_sha256": digest({p: x["sha256"] for p, x in elf.items()}),
            "python_source_count": len(sources),
            "python_inventory_sha256": digest(sources),
            "application_source_sha256": identity["source_tree_sha256"],
            "direct_consumers": direct,
            "effective_filesystem_entries": len(effective),
            "effective_filesystem_sha256": digest(effective)}


def verify_baseline(elf, sources, identity, baseline, effective_filesystem):
    observed = observed_baseline(elf, sources, identity, effective_filesystem)
    mismatches = [key for key, value in observed.items() if baseline.get(key) != value]
    if mismatches:
        raise ValueError("native review baseline drift: " + ", ".join(mismatches))
    _, transitive = consumer_paths(elf)
    return {**observed, "transitive_consumers": transitive}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "identity", "baseline", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    identity = json.loads(args.identity.read_bytes())
    with args.archive.open("rb") as stream:
        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != identity["archive_sha256"]:
            raise ValueError("archive identity mismatch")
    baseline = json.loads(args.baseline.read_bytes())
    if baseline["schema"] != 1:
        raise ValueError("unknown baseline schema")
    elf, sources, links, filesystem = inventory(args.archive)
    try:
        observed = verify_baseline(elf, sources, identity, baseline, filesystem)
    except ValueError as exc:
        # A failed gate is not a waived gate. Preserve the complete observed
        # baseline as well as the filesystem evidence so a reviewer can assess
        # every drift dimension rather than approving an inferred replacement.
        try:
            diagnostic_observed = observed_baseline(elf, sources, identity, filesystem)
        except ValueError:
            diagnostic_observed = None
        failed = {"schema": 1, "accepted": False, "failure": str(exc),
                  "expected_baseline": baseline,
                  "observed_baseline": diagnostic_observed,
                  "observed_filesystem_entries": len(filesystem),
                  "observed_filesystem_sha256": digest(filesystem),
                  "effective_filesystem": filesystem}
        args.output.write_text(json.dumps(failed, sort_keys=True, indent=2) + "\n")
        if diagnostic_observed is not None:
            print("OBSERVED BASELINE: " + json.dumps(diagnostic_observed, sort_keys=True))
        raise
    result = {"schema": 1, "accepted": True, "image_manifest_digest": identity["manifest_digest"],
              "archive_sha256": identity["archive_sha256"], "baseline_sha256": digest(baseline),
              "observed": observed, "elf": elf, "python_sources": sources, "links": links,
              "effective_filesystem": filesystem,
              "limitation": "Static linkage and exact code inventory; not proof of dynamic reachability."}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("VERIFIED: native and dependency source inventories match review baseline")


if __name__ == "__main__":
    main()
