"""Reference realm generation keeps rollover probing isolated and non-interactive."""
import json
import stat

from reference.realm import CLIENT, PROBE_CLIENT, prepare


def test_reference_realm_has_separate_least_privilege_rollover_probe(tmp_path):
    directory = tmp_path / "realm"
    prepare(directory)
    realm = json.loads((directory / "juniper-realm.json").read_text(encoding="utf-8"))
    probe = json.loads((directory / "probe.json").read_text(encoding="utf-8"))
    clients = {row["clientId"]: row for row in realm["clients"]}

    browser = clients[CLIENT]
    assert browser["publicClient"] is True
    assert browser["standardFlowEnabled"] is True
    assert browser["directAccessGrantsEnabled"] is False

    service = clients[PROBE_CLIENT]
    assert service["publicClient"] is False
    assert service["serviceAccountsEnabled"] is True
    assert service["standardFlowEnabled"] is False
    assert service["directAccessGrantsEnabled"] is False
    assert service["implicitFlowEnabled"] is False
    assert service["fullScopeAllowed"] is False
    assert probe["client_id"] == PROBE_CLIENT
    assert service["secret"] == probe["client_secret"]
    assert len(probe["client_secret"]) >= 32
    assert stat.S_IMODE((directory / "probe.json").stat().st_mode) == 0o600
