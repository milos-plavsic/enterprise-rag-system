"""Reject incomplete and stale security evidence before packaging."""
from datetime import datetime, timezone, timedelta

import pytest

from scripts.verify_scan_coverage import TRIVY, verify

NOW = datetime(2026, 11, 27, 13, tzinfo=timezone.utc)
STAMP = NOW.isoformat()
DIGEST = "sha256:" + "a" * 64


def fixture():
    grype = {"descriptor": {"name": "grype", "version": "0.110.0", "timestamp": STAMP,
        "configuration": {"only-fixed": False, "only-notfixed": False, "exclude": [],
            "vex-documents": [], "vex-add": [], "show-suppressed": True, "ignore": [],
            "db": {"validate-age": True, "validate-by-hash-on-start": True}},
        "db": {"status": {"valid": True, "built": STAMP,
            "from": "https://grype.anchore.io/db?checksum=" + DIGEST},
            "providers": {name: {"captured": STAMP} for name in ("alpine", "github", "nvd")}}},
        "distro": {"name": "alpine"}, "matches": []}
    apk = ["libssl3", "libcrypto3", "sqlite-libs"]
    py = ["fastapi"]
    identity = {"config_digest": DIGEST, "manifest_digest": DIGEST,
                "archive_sha256": DIGEST, "rootfs_diff_ids": [DIGEST]}
    trivy = {"SchemaVersion": 2, "Trivy": {"Version": "0.76.2"}, "CreatedAt": STAMP,
        "Metadata": {"OS": {"Family": "alpine"}, "ImageID": DIGEST, "DiffIDs": [DIGEST]},
        "Results": [
            {"Class": "os-pkgs", "Type": "alpine", "Packages": [{"Name": name, "Version": "1"} for name in apk]},
            {"Class": "lang-pkgs", "Type": "python-pkg", "Packages": [{"Name": name, "Version": "1"} for name in py]},
        ]}
    db = {"schema": 1, "scanner_image": TRIVY, "report_sha256": DIGEST,
          "archive_sha256": DIGEST, "database_sha256": DIGEST, "metadata_sha256": DIGEST,
          "metadata": {"Version": 2, "UpdatedAt": STAMP, "DownloadedAt": STAMP,
                       "NextUpdate": (NOW + timedelta(hours=6)).isoformat()}}
    packages = [(name, "pkg:apk/alpine/" + name) for name in apk] + [(name, "pkg:pypi/" + name) for name in py]
    spdx = {"packages": [{"name": name, "versionInfo": "1", "externalRefs": [
        {"referenceType": "purl", "referenceLocator": purl + "@1"}]} for name, purl in packages]}
    cdx = {"components": [{"name": name, "version": "1", "purl": purl + "@1"} for name, purl in packages]}
    return [grype, trivy, db, spdx, cdx, identity]


def test_complete_clean_scan_is_accepted():
    assert verify(*fixture(), DIGEST, NOW)["inventory_match"]


@pytest.mark.parametrize("case", ["stale_db", "missing_os", "missing_package", "ignored",
                                   "wrong_layer", "wrong_report", "filtered", "stale_grype"])
def test_incomplete_or_stale_scan_rejected(case):
    f = fixture()
    if case == "stale_db":
        f[2]["metadata"]["UpdatedAt"] = (NOW - timedelta(days=3)).isoformat()
    elif case == "missing_os":
        f[1]["Results"].pop(0)
    elif case == "missing_package":
        f[1]["Results"][0]["Packages"].pop()
    elif case == "ignored":
        f[0]["ignoredMatches"] = [{"vulnerability": {"severity": "High"}}]
    elif case == "wrong_layer":
        f[1]["Metadata"]["DiffIDs"] = ["sha256:" + "b" * 64]
    elif case == "wrong_report":
        f[2]["report_sha256"] = "sha256:" + "b" * 64
    elif case == "filtered":
        f[0]["descriptor"]["configuration"]["only-fixed"] = True
    else:
        f[0]["descriptor"]["db"]["status"]["built"] = (NOW - timedelta(days=3)).isoformat()
    with pytest.raises(ValueError):
        verify(*f, DIGEST, NOW)
