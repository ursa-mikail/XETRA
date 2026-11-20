import yaml
from pathlib import Path

TTP_PATH = Path(__file__).parent.parent / "xetra" / "ttp_library" / "artex_ttps.yaml"
VALID_STRATA = {"infra_network", "service", "system", "protocol", "algorithm", "software", "hardware"}


def load():
    with open(TTP_PATH) as f:
        return yaml.safe_load(f)


def test_ttp_library_loads():
    ttps = load()
    assert len(ttps) > 0


def test_every_entry_has_required_fields():
    for ttp in load():
        assert "id" in ttp
        assert "stratum" in ttp
        assert "attack_ids" in ttp and len(ttp["attack_ids"]) > 0
        assert "description" in ttp
        assert "expected_control" in ttp


def test_strata_are_valid():
    for ttp in load():
        assert ttp["stratum"] in VALID_STRATA, f"invalid stratum: {ttp['stratum']}"


def test_ids_are_unique():
    ids = [t["id"] for t in load()]
    assert len(ids) == len(set(ids))


def test_extended_library_loads_and_is_valid():
    ext_path = TTP_PATH.parent / "attack_enterprise.yaml"
    with open(ext_path) as f:
        ext = yaml.safe_load(f)
    assert len(ext) > 10
    for t in ext:
        assert t["stratum"] in VALID_STRATA
        assert len(t["attack_ids"]) > 0


def test_combined_library_has_no_duplicate_ids():
    ext_path = TTP_PATH.parent / "attack_enterprise.yaml"
    with open(ext_path) as f:
        ext = yaml.safe_load(f)
    core = load()
    all_ids = [t["id"] for t in core] + [t["id"] for t in ext]
    assert len(all_ids) == len(set(all_ids))
