import pytest

from vtx_detection_lab.parsers.rule_loader import (
    load_rules_from_dir,
    parse_wazuh_rules_xml,
)


def test_load_rules_from_catalog_dir():
    rules = load_rules_from_dir("rules/sigma_lite")

    assert len(rules) == 4
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"VTX-1001", "VTX-1002", "VTX-1003", "VTX-1004"}


def test_load_rules_rejects_duplicate_rule_id(tmp_path):
    rule_yaml = """
rule_id: VTX-9999
title: Duplicate Rule Test
description: Regra duplicada para teste de integridade.
severity: LOW
log_source: sysmon
mitre_tactic: Execution
mitre_technique: T1059.001
conditions:
  - field: EventID
    equals: "1"
"""
    (tmp_path / "a.yaml").write_text(rule_yaml, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(rule_yaml, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicado"):
        load_rules_from_dir(tmp_path)


def test_load_rules_rejects_invalid_regex(tmp_path):
    bad_regex_yaml = """
rule_id: VTX-9998
title: Invalid Regex Test
description: Regex propositalmente quebrada.
severity: MEDIUM
log_source: linux_auth
mitre_tactic: Credential Access
mitre_technique: T1110.001
conditions:
  - field: message
    regex: "[unclosed-group"
"""
    (tmp_path / "bad.yaml").write_text(bad_regex_yaml, encoding="utf-8")

    with pytest.raises(ValueError, match="Regex inválida"):
        load_rules_from_dir(tmp_path)


def test_load_rules_raises_for_missing_directory():
    with pytest.raises(FileNotFoundError):
        load_rules_from_dir("rules/diretorio_inexistente")


def test_wazuh_xml_is_valid_and_aligned_with_yaml_catalog():
    yaml_rules = load_rules_from_dir("rules/sigma_lite")
    wazuh_rules = parse_wazuh_rules_xml("rules/wazuh/local_rules.xml")

    assert len(wazuh_rules) == len(yaml_rules)

    yaml_mitre = {r.mitre_technique for r in yaml_rules}
    wazuh_mitre = {r["mitre_technique"] for r in wazuh_rules}
    assert wazuh_mitre == yaml_mitre
