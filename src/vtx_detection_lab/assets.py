from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

AssetEnvironment = Literal["prod", "staging", "dev"]
AssetExposure = Literal["internet", "internal"]
AssetBusinessCriticality = Literal["critical", "high", "medium", "low"]

UNKNOWN_ASSET_ID = "unknown-asset"
ASSET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class AssetInventoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    asset_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description="Identificador único do ativo compatível com a suíte vtx-*.",
    )
    name: str = Field(..., min_length=1, max_length=120)
    owner: str = Field(..., min_length=1, max_length=120)
    environment: AssetEnvironment
    exposure: AssetExposure
    criticality: AssetBusinessCriticality
    hosts: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["1"] = "1"
    assets: list[AssetInventoryEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> AssetInventory:
        seen_ids: set[str] = set()
        dup_ids: set[str] = set()
        seen_hosts: set[str] = set()
        dup_hosts: set[str] = set()

        for asset in self.assets:
            if asset.asset_id in seen_ids:
                dup_ids.add(asset.asset_id)
            seen_ids.add(asset.asset_id)

            for host in asset.hosts:
                norm_host = host.strip().lower()
                if not norm_host:
                    continue
                if norm_host in seen_hosts:
                    dup_hosts.add(norm_host)
                seen_hosts.add(norm_host)

        if dup_ids:
            raise ValueError(f"Duplicate asset_id entries found: {', '.join(sorted(dup_ids))}")
        if dup_hosts:
            raise ValueError(f"Duplicate host mappings found: {', '.join(sorted(dup_hosts))}")
        return self

    def by_host(self) -> dict[str, AssetInventoryEntry]:
        mapping: dict[str, AssetInventoryEntry] = {}
        for asset in self.assets:
            for host in asset.hosts:
                norm = host.strip().lower()
                if norm:
                    mapping[norm] = asset
        return mapping

    def resolve_host(self, host: str) -> Optional[AssetInventoryEntry]:
        if not host or not host.strip():
            return None
        return self.by_host().get(host.strip().lower())


def load_asset_inventory(path: str | Path) -> AssetInventory:
    inv_path = Path(path)
    data = yaml.safe_load(inv_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Asset inventory at '{inv_path}' must be a YAML mapping.")
    return AssetInventory.model_validate(data)


def resolve_asset_id(
    host: str,
    inventory: Optional[AssetInventory] = None,
    explicit_asset_id: Optional[str] = None,
) -> str:
    if explicit_asset_id and ASSET_ID_RE.match(explicit_asset_id.strip()):
        return explicit_asset_id.strip()

    if inventory is not None:
        matched = inventory.resolve_host(host)
        if matched is not None:
            return matched.asset_id

    return UNKNOWN_ASSET_ID
