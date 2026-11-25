from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from vtx_detection_lab.models import DetectionRule


def _validate_condition_regexes(rule: DetectionRule) -> None:
    for cond in rule.conditions:
        if cond.regex:
            try:
                re.compile(cond.regex)
            except re.error as exc:
                raise ValueError(
                    f"Regex inválida na regra {rule.rule_id} (campo '{cond.field}'): {exc}"
                ) from exc


def load_rule_file(rule_path: str | Path) -> DetectionRule:
    """Carrega e valida um único arquivo YAML de regra Detection-as-Code."""
    path = Path(rule_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de regra não encontrado: {path}")

    with path.open("r", encoding="utf-8") as file:
        raw_data = yaml.safe_load(file)

    if not isinstance(raw_data, dict):
        raise ValueError(f"Estrutura YAML inválida em {path}: esperado mapeamento de chaves.")

    rule = DetectionRule(**raw_data)
    _validate_condition_regexes(rule)
    return rule


def load_rules_from_dir(rules_dir: str | Path = "rules/sigma_lite") -> list[DetectionRule]:
    """Carrega todas as regras YAML de um diretório garantindo unicidade de rule_id."""
    directory = Path(rules_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Diretório de regras não encontrado: {directory}")

    yaml_files = sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.yml")))
    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()

    for path in yaml_files:
        rule = load_rule_file(path)
        if rule.rule_id in seen_ids:
            raise ValueError(f"rule_id duplicado encontrado no catálogo: {rule.rule_id}")
        seen_ids.add(rule.rule_id)
        rules.append(rule)

    return rules


def parse_wazuh_rules_xml(xml_path: str | Path = "rules/wazuh/local_rules.xml") -> list[dict[str, str]]:
    """Valida a estrutura XML das regras Wazuh e retorna metadados principais (id, level, mitre)."""
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo XML do Wazuh não encontrado: {path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"XML do Wazuh malformado em {path}: {exc}") from exc

    root = tree.getroot()
    parsed: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    for elem in root.findall(".//rule"):
        rule_id = elem.attrib.get("id", "").strip()
        level = elem.attrib.get("level", "").strip()
        if not rule_id or not level:
            raise ValueError("Regra Wazuh sem atributo obrigatório 'id' ou 'level'.")
        if rule_id in seen_ids:
            raise ValueError(f"ID de regra Wazuh duplicado: {rule_id}")
        seen_ids.add(rule_id)

        mitre_elem = elem.find("./mitre/id")
        desc_elem = elem.find("./description")
        parsed.append(
            {
                "id": rule_id,
                "level": level,
                "mitre_technique": mitre_elem.text.strip().upper() if mitre_elem is not None and mitre_elem.text else "",
                "description": desc_elem.text.strip() if desc_elem is not None and desc_elem.text else "",
            }
        )

    return parsed
