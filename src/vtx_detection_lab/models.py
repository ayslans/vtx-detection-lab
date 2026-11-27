from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from vtx_detection_lab.assets import UNKNOWN_ASSET_ID

MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class LogSource(str, Enum):
    SYSMON = "sysmon"
    LINUX_AUTH = "linux_auth"
    AUDITD = "auditd"
    WAZUH = "wazuh"
    NGINX = "nginx"
    FASTAPI = "fastapi"


class DetectionCondition(BaseModel):
    field: str = Field(..., min_length=1)
    contains_any: list[str] = Field(default_factory=list)
    equals: Optional[str] = None
    regex: Optional[str] = None


class DetectionRule(BaseModel):
    rule_id: str = Field(..., min_length=3)
    title: str = Field(..., min_length=5)
    description: str
    severity: Severity
    log_source: LogSource
    mitre_tactic: str = Field(..., min_length=3)
    mitre_technique: str
    pci_dss_refs: list[str] = Field(default_factory=list)
    nist_csf_refs: list[str] = Field(default_factory=list)
    conditions: list[DetectionCondition] = Field(..., min_length=1)
    false_positive_notes: Optional[str] = None

    @field_validator("mitre_technique")
    @classmethod
    def validate_mitre_id(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not MITRE_TECHNIQUE_RE.match(normalized):
            raise ValueError(f"ID MITRE ATT&CK inválido: {value}")
        return normalized


class TelemetryEvent(BaseModel):
    event_id: str
    timestamp: str
    host: str
    log_source: LogSource
    payload: dict[str, Any]
    expected_rule_id: Optional[str] = None
    asset_id: Optional[str] = None


class AlertMatch(BaseModel):
    source: str = "vtx-detection-lab"
    rule_id: str
    rule_title: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    event_id: str
    host: str
    asset_id: str = UNKNOWN_ASSET_ID
    timestamp: str
    matched_fields: dict[str, Any] = Field(default_factory=dict)
    event_payload: dict[str, Any] = Field(default_factory=dict)
