from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from vtx_detection_lab.assets import AssetInventory, resolve_asset_id
from vtx_detection_lab.models import LogSource, TelemetryEvent

NGINX_COMBINED_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"$'
)

UVICORN_ACCESS_RE = re.compile(
    r'^(?:(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+)?'
    r'(?:[A-Z]+:\s+)?(?P<src_ip>\S+?)(?::\d+)?\s+-\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3}).*$'
)


class NormalizeSource(str, Enum):
    AUTO = "auto"
    NGINX = "nginx"
    FASTAPI = "fastapi"


class NormalizationResult(BaseModel):
    events: list[TelemetryEvent] = Field(default_factory=list)
    total_lines: int = 0
    parsed_lines: int = 0
    skipped_lines: int = 0


def _to_iso_utc(raw_ts: Optional[str]) -> str:
    if not raw_ts or not raw_ts.strip():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cleaned = raw_ts.strip()
    try:
        dt = datetime.strptime(cleaned, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    try:
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_uri(full_uri: str) -> tuple[str, str]:
    if "?" in full_uri:
        path, query = full_uri.split("?", 1)
        return path, query
    return full_uri, ""


def _make_event_id(source: LogSource, host: str, timestamp: str, raw_line: str) -> str:
    prefix = "NORM-NGX" if source == LogSource.NGINX else "NORM-API"
    digest = hashlib.sha256(
        f"{source.value}|{host}|{timestamp}|{raw_line}".encode("utf-8")
    ).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_json_line(
    line: str,
    requested_source: NormalizeSource,
    host: str,
    asset_id: str,
) -> Optional[TelemetryEvent]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    method = str(obj.get("http_method") or obj.get("method") or "").upper().strip()
    full_uri = str(
        obj.get("full_uri")
        or obj.get("request_uri")
        or obj.get("uri")
        or obj.get("path")
        or ""
    ).strip()
    status_raw = obj.get("http_status", obj.get("status_code", obj.get("status")))
    if not method or not full_uri or status_raw is None:
        return None

    if requested_source == NormalizeSource.NGINX:
        source = LogSource.NGINX
    elif requested_source == NormalizeSource.FASTAPI:
        source = LogSource.FASTAPI
    else:
        source = (
            LogSource.NGINX
            if ("remote_addr" in obj or "http_user_agent" in obj or "time_iso8601" in obj)
            else LogSource.FASTAPI
        )

    ts = _to_iso_utc(
        str(obj.get("timestamp") or obj.get("time_iso8601") or obj.get("ts") or "")
    )
    http_path, query_string = _split_uri(full_uri)
    if not query_string and obj.get("query_string"):
        query_string = str(obj["query_string"])
        full_uri = f"{http_path}?{query_string}"

    payload = {
        "event_category": "http_access",
        "src_ip": str(obj.get("src_ip") or obj.get("client_ip") or obj.get("remote_addr") or "-"),
        "http_method": method,
        "http_path": http_path,
        "query_string": query_string,
        "full_uri": full_uri,
        "http_status": _safe_int(status_raw),
        "bytes_sent": _safe_int(obj.get("bytes_sent", obj.get("body_bytes_sent", 0))),
        "user_agent": str(obj.get("user_agent") or obj.get("http_user_agent") or "-"),
        "referer": str(obj.get("referer") or obj.get("http_referer") or "-"),
        "raw_line": line,
    }

    return TelemetryEvent(
        event_id=_make_event_id(source, host, ts, line),
        timestamp=ts,
        host=host,
        asset_id=asset_id,
        log_source=source,
        payload=payload,
    )


def _parse_nginx_text_line(line: str, host: str, asset_id: str) -> Optional[TelemetryEvent]:
    match = NGINX_COMBINED_RE.match(line)
    if not match:
        return None

    ts = _to_iso_utc(match.group("ts"))
    full_uri = match.group("uri")
    http_path, query_string = _split_uri(full_uri)
    bytes_raw = match.group("bytes")

    payload = {
        "event_category": "http_access",
        "src_ip": match.group("src_ip"),
        "http_method": match.group("method"),
        "http_path": http_path,
        "query_string": query_string,
        "full_uri": full_uri,
        "http_status": int(match.group("status")),
        "bytes_sent": 0 if bytes_raw == "-" else int(bytes_raw),
        "user_agent": match.group("ua") or "-",
        "referer": match.group("referer") or "-",
        "raw_line": line,
    }

    return TelemetryEvent(
        event_id=_make_event_id(LogSource.NGINX, host, ts, line),
        timestamp=ts,
        host=host,
        asset_id=asset_id,
        log_source=LogSource.NGINX,
        payload=payload,
    )


def _parse_uvicorn_text_line(line: str, host: str, asset_id: str) -> Optional[TelemetryEvent]:
    match = UVICORN_ACCESS_RE.match(line)
    if not match:
        return None

    ts = _to_iso_utc(match.group("ts"))
    full_uri = match.group("uri")
    http_path, query_string = _split_uri(full_uri)

    payload = {
        "event_category": "http_access",
        "src_ip": match.group("src_ip"),
        "http_method": match.group("method"),
        "http_path": http_path,
        "query_string": query_string,
        "full_uri": full_uri,
        "http_status": int(match.group("status")),
        "bytes_sent": 0,
        "user_agent": "-",
        "referer": "-",
        "raw_line": line,
    }

    return TelemetryEvent(
        event_id=_make_event_id(LogSource.FASTAPI, host, ts, line),
        timestamp=ts,
        host=host,
        asset_id=asset_id,
        log_source=LogSource.FASTAPI,
        payload=payload,
    )


def normalize_log_line(
    line: str,
    source: NormalizeSource = NormalizeSource.AUTO,
    host: str = "UNKNOWN-HOST",
    asset_id: str = "unknown-asset",
) -> Optional[TelemetryEvent]:
    stripped = line.strip()
    if not stripped:
        return None

    if stripped.startswith("{") and stripped.endswith("}"):
        return _parse_json_line(stripped, source, host, asset_id)

    if source == NormalizeSource.NGINX:
        return _parse_nginx_text_line(stripped, host, asset_id)
    if source == NormalizeSource.FASTAPI:
        return _parse_uvicorn_text_line(stripped, host, asset_id)

    return _parse_nginx_text_line(stripped, host, asset_id) or _parse_uvicorn_text_line(
        stripped, host, asset_id
    )


def normalize_log_file(
    input_path: str | Path,
    source: NormalizeSource = NormalizeSource.AUTO,
    host: str = "UNKNOWN-HOST",
    asset_inventory: Optional[AssetInventory] = None,
    explicit_asset_id: Optional[str] = None,
) -> NormalizationResult:
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de log não encontrado: {path}")

    resolved_asset_id = resolve_asset_id(
        host=host,
        inventory=asset_inventory,
        explicit_asset_id=explicit_asset_id,
    )

    events: list[TelemetryEvent] = []
    total_lines = 0
    skipped_lines = 0

    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        total_lines += 1
        event = normalize_log_line(
            raw,
            source=source,
            host=host,
            asset_id=resolved_asset_id,
        )
        if event is None:
            skipped_lines += 1
        else:
            events.append(event)

    return NormalizationResult(
        events=events,
        total_lines=total_lines,
        parsed_lines=len(events),
        skipped_lines=skipped_lines,
    )


def save_telemetry_jsonl(events: list[TelemetryEvent], output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(evt.model_dump(mode="json", exclude_none=True), ensure_ascii=False)
        for evt in events
    ]
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out
