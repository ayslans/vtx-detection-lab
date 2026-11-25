import pytest
from pydantic import ValidationError

from vtx_detection_lab.models import (
    DetectionCondition,
    DetectionRule,
    LogSource,
    Severity,
)


def _base_rule(**overrides):
    data = {
        "rule_id": "VTX-1001",
        "title": "Encoded PowerShell Execution",
        "description": "Detecta execução de PowerShell com comando codificado em Base64.",
        "severity": Severity.HIGH,
        "log_source": LogSource.SYSMON,
        "mitre_tactic": "Execution",
        "mitre_technique": "t1059.001",
        "pci_dss_refs": ["Req. 10.2.1", "Req. 11.5"],
        "nist_csf_refs": ["DE.CM-09"],
        "conditions": [
            DetectionCondition(field="CommandLine", contains_any=["-enc", "-EncodedCommand"])
        ],
    }
    data.update(overrides)
    return DetectionRule(**data)


def test_detection_rule_normalizes_mitre_technique():
    rule = _base_rule(mitre_technique="  t1059.001 ")
    assert rule.mitre_technique == "T1059.001"


def test_detection_rule_accepts_parent_mitre_technique():
    rule = _base_rule(mitre_technique="T1003")
    assert rule.mitre_technique == "T1003"


def test_detection_rule_rejects_invalid_mitre_id():
    with pytest.raises(ValidationError):
        _base_rule(mitre_technique="ATT&CK-999")


def test_detection_rule_requires_at_least_one_condition():
    with pytest.raises(ValidationError):
        _base_rule(conditions=[])
