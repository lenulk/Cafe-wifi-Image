"""สถานะ collector แบบไฟล์ขนาดเล็ก เพื่อให้หน้า Admin ตรวจความคืบหน้าได้แม้ DB ล่ม."""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cafe-wifi.telemetry")


class CollectorTelemetry:
    def __init__(self, name: str, directory: str | os.PathLike | None = None):
        if name not in {"conn", "dns"}:
            raise ValueError(name)
        self.path = Path(directory or os.environ.get("LOG_DIR", "/var/log/cafe-wifi")) / f"collector-{name}.json"
        self.name = name
        self.received = self.written = self.dropped = self.unmapped = 0
        self.last_event_at = self.last_write_at = None
        self.last_error = None
        self._last_heartbeat = 0.0

    def previous_heartbeat(self) -> str | None:
        """R2-06: heartbeat ล่าสุดของรอบก่อน (อ่านก่อนเขียนทับ) = จุดที่ collector เงียบไป"""
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))["heartbeat_at"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def event(self) -> None:
        self.received += 1
        self.last_event_at = datetime.now().isoformat()

    def write(self, count: int) -> None:
        self.written += count
        if count:
            self.last_write_at = datetime.now().isoformat()
            self.last_error = None

    def drop(self, count: int) -> None:
        self.dropped += count
        self.last_error = f"ทิ้ง {count} เหตุการณ์ล่าสุด"

    def missing_mac(self, count: int) -> None:
        self.unmapped += count

    def error(self, detail: str) -> None:
        self.last_error = detail[:200]

    def heartbeat(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < 5:
            return
        self._last_heartbeat = now
        data = dict(name=self.name, heartbeat_at=datetime.now().isoformat(),
                    received=self.received, written=self.written, dropped=self.dropped,
                    unmapped=self.unmapped, last_event_at=self.last_event_at,
                    last_write_at=self.last_write_at, last_error=self.last_error)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("บันทึกสถานะ %s ไม่สำเร็จ: %s", self.name, exc)


def read_collector_status(directory: str | os.PathLike,
                          now: datetime | None = None) -> dict[str, dict]:
    now = now or datetime.now()
    result = {}
    for name in ("conn", "dns"):
        path = Path(directory) / f"collector-{name}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            age = (now - datetime.fromisoformat(data["heartbeat_at"])).total_seconds()
            data["healthy"] = 0 <= age <= 20
            data["age_seconds"] = int(age)
        except (OSError, ValueError, KeyError, TypeError):
            data = dict(name=name, healthy=False, age_seconds=None,
                        received=0, written=0, dropped=0, unmapped=0,
                        last_write_at=None, last_error="ยังไม่พบ heartbeat")
        result[name] = data
    return result
