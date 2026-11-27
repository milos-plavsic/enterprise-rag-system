"""Collect fail-closed runtime evidence for OpenSSL reachability dispositions."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

APP = Path("/app")
ALLOWED_SYSTEM_OPENSSL_CONSUMERS = ("_ssl.", "_hashlib.")
SOURCE_MARKERS = {
    "quic": ("aioquic", "ssl_quic", "ossl_quic", "http3", "http/3"),
    "dane": ("ssl_dane", "tlsa", "dane"),
    "cms_pkcs7": ("cms_", "pkcs7_", "cms.", "pkcs7."),
    "crl": ("verify_crl_check", "x509_v_flag_crl_check", "verify_flags"),
    "pem_stack": ("pem_x509_info",),
    "suite_b": (
        "ssl_ctx_set_cert_flags", "ssl_cert_flag_suiteb_128_los",
        "suiteb_128_los", "suiteb",
    ),
    "native": ("ctypes.", "ctypes import", "cffi.", "cffi import"),
}


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True, timeout=10)
    return result.stdout + result.stderr


def app_sources() -> tuple[str, str]:
    files = sorted(
        p for p in APP.rglob("*")
        if p.is_file() and p.suffix.casefold() in {".py", ".js", ".html"} and "__pycache__" not in p.parts
    )
    digest = hashlib.sha256()
    text = []
    for path in files:
        data = path.read_bytes()
        digest.update(str(path.relative_to(APP)).encode() + b"\0" + data + b"\0")
        text.append(data.decode("utf-8", errors="replace").casefold())
    return "\n".join(text), "sha256:" + digest.hexdigest()


def elf_consumers() -> list[dict]:
    ldd = shutil.which("ldd")
    if not ldd:
        raise RuntimeError("ldd unavailable")
    roots = [Path(sys.prefix), APP]
    rows = []
    seen: set[Path] = set()
    for root in roots:
        for path in root.rglob("*"):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            try:
                with path.open("rb") as stream:
                    if stream.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            result = subprocess.run([ldd, str(path)], text=True, capture_output=True, timeout=3)
            output = (result.stdout + result.stderr).strip()
            if "libssl.so.3" in output or "libcrypto.so.3" in output:
                rows.append({"path": str(path), "ldd": output})
    return sorted(rows, key=lambda row: row["path"])


def exact_apk(package: str, version: str) -> bool:
    result = subprocess.run(["apk", "info", "-e", f"{package}={version}"], capture_output=True)
    return result.returncode == 0


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: openssl_reachability.py IMAGE_INSPECT_JSON IDENTITY_JSON POLICY_JSON OUTPUT_JSON")
    inspect_path, identity_path, policy_path, output_path = map(Path, sys.argv[1:])
    identity = json.loads(identity_path.read_bytes())
    policy = json.loads(policy_path.read_bytes())
    binding_keys = ("config_digest", "manifest_digest", "archive_sha256", "local_image_id", "source_commit",
                    "source_tree_sha256", "collector_sha256", "policy_sha256")
    binding = {key: identity[key] for key in binding_keys}
    collector_hash = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    policy_hash = "sha256:" + hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if collector_hash != binding["collector_sha256"] or policy_hash != binding["policy_sha256"]:
        raise RuntimeError("collector or disposition policy differs from exact Git tree")
    image = json.loads(inspect_path.read_text(encoding="utf-8"))
    if not isinstance(image, list) or len(image) != 1:
        raise RuntimeError("unexpected Docker image inspect payload")
    if image[0].get("Id") != binding["local_image_id"]:
        raise RuntimeError("runtime Docker image ID differs from verified local identity")
    if (image[0].get("RootFS") or {}).get("Layers") != identity["rootfs_diff_ids"]:
        raise RuntimeError("runtime rootfs differs from verified archive")
    config = image[0].get("Config", {})
    command = config.get("Cmd")
    if not isinstance(command, list):
        raise RuntimeError("image command missing")
    try:
        protocol_index = command.index("--http")
    except ValueError as exc:
        raise RuntimeError("Uvicorn HTTP protocol is not explicitly pinned") from exc
    if protocol_index + 1 >= len(command) or command[protocol_index + 1] != "h11":
        raise RuntimeError("production HTTP protocol is not h11")

    source, source_digest = app_sources()
    if source_digest != binding["source_tree_sha256"]:
        raise RuntimeError("runtime source differs from immutable Git source tree")
    markers = {
        name: sorted(marker for marker in values if marker in source)
        for name, values in SOURCE_MARKERS.items()
    }
    installed = {dist.metadata.get("Name", "").casefold(): dist.version for dist in importlib.metadata.distributions()}
    quic_packages = sorted(name for name in installed if "quic" in name or name in {"aioquic", "http3"})
    ssl_api = sorted(name for name in dir(ssl) if any(term in name.casefold() for term in ("quic", "dane", "cms", "pkcs7")))

    consumers = elf_consumers()
    unexpected = [
        row["path"] for row in consumers
        if not os.path.basename(row["path"]).startswith(ALLOWED_SYSTEM_OPENSSL_CONSUMERS)
    ]

    # Inspect cryptography in a fresh interpreter. Alpine/musl ldd can return
    # 127 for extension modules even when they load correctly; /proc/self/maps
    # gives direct evidence of which system OpenSSL DSOs the binding actually maps.
    probe = (
        "import json; import cryptography.hazmat.bindings._rust as binding; "
        "maps=open('/proc/self/maps', encoding='utf-8').read().splitlines(); "
        "rows=sorted({line.rsplit(None,1)[-1] for line in maps "
        "if 'libssl.so.3' in line or 'libcrypto.so.3' in line}); "
        "print(json.dumps({'binding': binding.__file__, 'system_openssl_maps': rows}))"
    )
    try:
        cryptography_probe = json.loads(run(sys.executable, "-I", "-c", probe))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise RuntimeError("cannot inspect cryptography native binding") from exc
    cryptography_maps = cryptography_probe.get("system_openssl_maps")
    if not isinstance(cryptography_maps, list) or any(not isinstance(row, str) for row in cryptography_maps):
        raise RuntimeError("invalid cryptography native binding evidence")

    sqlite_version = __import__("sqlite3").sqlite_version
    openssl_version = ssl.OPENSSL_VERSION
    package_ok = exact_apk("libcrypto3", "3.5.9-r1") and exact_apk("libssl3", "3.5.9-r1")
    if not package_ok or not openssl_version.startswith("OpenSSL 3.5.9 "):
        raise RuntimeError("runtime OpenSSL package/version drift")

    invariants = {
        "no_quic_stack": (
            not quic_packages and not markers["quic"] and not markers["native"]
            and not any("quic" in name.casefold() for name in ssl_api)
            and command[protocol_index + 1] == "h11"
        ),
        "no_dane_api": (
            not markers["dane"] and not markers["native"]
            and not any("dane" in name.casefold() for name in ssl_api)
        ),
        "no_cms_pkcs7_api": (
            not markers["cms_pkcs7"] and not markers["native"]
            and not any(term in name.casefold() for name in ssl_api for term in ("cms", "pkcs7"))
        ),
        "no_crl_check_configuration": not markers["crl"] and not markers["native"],
        "no_direct_pem_stack_api": not markers["pem_stack"] and not markers["native"],
        "no_suite_b_certificate_flag": not markers["suite_b"] and not markers["native"],
        "python_tls_ca_loader_only": (
            not unexpected
            and not cryptography_maps
            and not markers["native"]
        ),
        "sqlite_cli_absent": shutil.which("sqlite3") is None,
        "sqlite_runtime_patched": tuple(map(int, sqlite_version.split("."))) >= (3, 54, 1),
    }
    failed = sorted(name for name, value in invariants.items() if not value)

    evidence = {
        "schema": 1,
        "image_binding": binding,
        "source_tree_sha256": source_digest,
        "python": sys.version,
        "openssl": openssl_version,
        "sqlite": sqlite_version,
        "image_user": config.get("User"),
        "image_command": command,
        "packages": {"libcrypto3": "3.5.9-r1", "libssl3": "3.5.9-r1"},
        "python_ssl_api_markers": ssl_api,
        "quic_packages": quic_packages,
        "source_markers": markers,
        "system_openssl_consumers": consumers,
        "unexpected_system_openssl_consumers": unexpected,
        "cryptography_native_binding": cryptography_probe,
        "invariants": invariants,
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if str(output_path) == "-":
        sys.stdout.write(rendered)
        sys.stdout.flush()
    else:
        output_path.write_text(rendered, encoding="utf-8")
    if failed:
        raise RuntimeError("reachability invariants failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
