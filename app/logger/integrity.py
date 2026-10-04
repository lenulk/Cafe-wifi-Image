"""
logger/integrity.py — hash chain รายวันของไฟล์ log เพื่อพิสูจน์ว่าไม่ถูกแก้ไขย้อนหลัง
(ตอบโจทย์ "log ต้องแก้ไขไม่ได้" ใน §6.1 ของ PROJECT_PLAN.md)

หลักการ: ทุกครั้งที่มีไฟล์ log ใหม่ถูกหมุน (logrotate) ให้คำนวณ SHA-256 ของไฟล์นั้น
ผูกกับ SHA-256 ของไฟล์ก่อนหน้า (prev_sha256) แล้วบันทึกเป็นแถวใน manifest
ถ้าใครย้อนไปแก้ไฟล์เก่า SHA-256 ที่คำนวณใหม่จะไม่ตรงกับที่บันทึกไว้ -> ตรวจพบทันที

ออกแบบให้ตรรกะหลัก (คำนวณ hash, ตรวจสาย hash) แยกจากที่เก็บข้อมูล (DB) ผ่าน interface
ManifestStore เพื่อให้ทดสอบได้โดยไม่ต้องมี MariaDB จริง — SqlManifestStore คือ
ตัวที่ใช้งานจริงบน gateway, MemoryManifestStore ใช้ในเทสต์ (และเป็น fallback ฉุกเฉินได้)
"""
from __future__ import annotations

import gzip
import hashlib
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Protocol

log = logging.getLogger("cafe-wifi.integrity")

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    """SHA-256 ของเนื้อไฟล์ — ถ้าเป็น .gz จะ hash เนื้อหาที่ decompress แล้ว (เสถียรกว่า
    hash ตัวบีบอัดเอง เพราะ gzip header มี timestamp ที่เปลี่ยนได้แม้เนื้อหาเหมือนเดิม)"""
    h = hashlib.sha256()
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rb") as f:  # type: ignore[arg-type]
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class ManifestEntry:
    filename: str
    sha256: str
    prev_sha256: str | None
    size_bytes: int
    deletion_state: str = "active"
    sealed_at: datetime | None = None


class ManifestStore(Protocol):
    def last_entry(self) -> ManifestEntry | None: ...
    def has(self, filename: str) -> bool: ...
    def add(self, entry: ManifestEntry) -> None: ...
    def all_entries(self) -> list[ManifestEntry]: ...
    def set_deletion(self, filename: str, state: str) -> None: ...


class MemoryManifestStore:
    """ใช้ในเทสต์ (และเป็น fallback ได้ถ้า DB ล่มชั่วคราว แต่ข้อมูลจะหายเมื่อ process ตาย)"""

    def __init__(self) -> None:
        self._entries: list[ManifestEntry] = []

    def last_entry(self) -> ManifestEntry | None:
        return self._entries[-1] if self._entries else None

    def has(self, filename: str) -> bool:
        return any(e.filename == filename for e in self._entries)

    def add(self, entry: ManifestEntry) -> None:
        self._entries.append(entry)

    def all_entries(self) -> list[ManifestEntry]:
        return list(self._entries)

    def set_deletion(self, filename: str, state: str) -> None:
        from dataclasses import replace
        self._entries = [replace(e, deletion_state=state) if e.filename == filename else e
                         for e in self._entries]


class SqlManifestStore:
    """ตัวจริงที่ใช้งานบน gateway — เขียน/อ่านตาราง log_manifest ผ่าน common.db"""

    def last_entry(self) -> ManifestEntry | None:
        from common.db import query_one
        row = query_one("SELECT filename, sha256, prev_sha256, size_bytes, deletion_state, sealed_at "
                        "FROM log_manifest ORDER BY id DESC LIMIT 1")
        return ManifestEntry(**row) if row else None

    def has(self, filename: str) -> bool:
        from common.db import query_one
        return query_one("SELECT id FROM log_manifest WHERE filename=%s", (filename,)) is not None

    def add(self, entry: ManifestEntry) -> None:
        from datetime import date

        from common.db import execute
        execute("INSERT INTO log_manifest (log_date, filename, sha256, prev_sha256, size_bytes) "
                "VALUES (%s,%s,%s,%s,%s)",
                (date.today(), entry.filename, entry.sha256, entry.prev_sha256, entry.size_bytes))

    def all_entries(self) -> list[ManifestEntry]:
        from common.db import query_all
        rows = query_all("SELECT filename, sha256, prev_sha256, size_bytes, deletion_state, sealed_at "
                         "FROM log_manifest ORDER BY id ASC")
        return [ManifestEntry(**r) for r in rows]

    def set_deletion(self, filename: str, state: str) -> None:
        from common.db import execute
        if state == "deleted":
            n = execute("UPDATE log_manifest SET deletion_state='deleted', deleted_at=NOW() "
                        "WHERE filename=%s AND deletion_state='pending'", (filename,))
        elif state == "pending":
            n = execute("UPDATE log_manifest SET deletion_state='pending' "
                        "WHERE filename=%s AND deletion_state='active'", (filename,))
        else:
            raise ValueError(state)
        if n != 1:
            raise RuntimeError(f"ไม่สามารถเปลี่ยนสถานะการลบของ {filename} เป็น {state}")


def seal_directory(
    directory: Path,
    store: ManifestStore,
    # แก้บั๊ก C1: ของเดิม ("*.log.gz", "*.log") ไม่ตรงกับไฟล์ที่ logrotate สร้างจริงเลยสักไฟล์
    # เพราะ install.sh ตั้ง `dateext` + `dateformat -%Y-%m-%d` ไว้ ชื่อไฟล์จึงเป็น
    # "dnsmasq.log-2026-08-25.gz" (มี -YYYY-MM-DD คั่นก่อน .gz เสมอ) หรือช่วง delaycompress
    # รอบแรกจะเป็น "dnsmasq.log-2026-08-25" (ยังไม่ compress) -- ผลคือ seal_directory()
    # ไม่เคยผนึกไฟล์อะไรเลยบนเครื่องจริง ทั้งที่เทสต์ผ่านหมดเพราะเทสต์ใช้ชื่อไฟล์สมมติ
    # "day1.log" ที่ไม่ตรงกับรูปแบบจริงของ logrotate
    patterns: tuple[str, ...] = ("*.log-*.gz", "*.log-*", "*.log.gz", "*.log"),
) -> list[ManifestEntry]:
    """
    เดินดูไฟล์ที่ยังไม่เคยผนึกในไดเรกทอรี (เรียงตาม mtime เก่า->ใหม่ เพื่อให้สาย hash
    เรียงตามเวลาจริง) แล้วผนึกทีละไฟล์ต่อจาก prev hash ล่าสุด คืนรายการที่เพิ่งผนึกใหม่
    """
    candidates: list[Path] = []
    for pat in patterns:
        candidates.extend(directory.glob(pat))
    candidates.sort(key=lambda p: p.stat().st_mtime)

    sealed: list[ManifestEntry] = []
    prev = store.last_entry()
    prev_hash = prev.sha256 if prev else None
    sealed_hash = {e.filename: e.sha256 for e in store.all_entries()}

    for path in candidates:
        if store.has(path.name):
            continue
        digest = sha256_file(path)
        # N25: logrotate ตั้ง delaycompress ไว้ ไฟล์ที่หมุนรอบก่อน (X.log-DATE) จะถูกบีบอัดเป็น
        # X.log-DATE.gz ในรอบถัดไป ถ้าเนื้อหาเหมือนตอนผนึกทุกไบต์ (sha256_file hash เนื้อหาที่
        # decompress แล้ว) ก็คือไฟล์เดิมที่แค่เปลี่ยนชื่อ ไม่ต้องผนึกซ้ำ -- verify_chain() ตาม
        # ชื่อ .gz ให้เอง ถ้าเนื้อหาต่างไปจะผนึกเป็นรายการใหม่ และชื่อเดิมจะถูกฟ้อง hash_mismatch
        if path.name.endswith(".gz") and sealed_hash.get(path.name[:-3]) == digest:
            continue
        entry = ManifestEntry(filename=path.name, sha256=digest,
                              prev_sha256=prev_hash, size_bytes=path.stat().st_size)
        store.add(entry)
        sealed.append(entry)
        prev_hash = digest
        log.info("ผนึก log %s -> %s", path.name, digest[:16])
    return sealed


@dataclass(frozen=True)
class IntegrityIssue:
    filename: str
    kind: str    # 'hash_mismatch' | 'missing_file' | 'chain_broken'
    detail: str


def verify_chain(store: ManifestStore, directory: Path) -> list[IntegrityIssue]:
    """
    ตรวจทั้งสาย: ไฟล์ยังอยู่ไหม, hash ยังตรงกับที่บันทึกไว้ไหม, prev_sha256 ต่อกันถูกไหม
    คืน list ว่างแปลว่าผ่านหมด — ใช้เป็นหลักฐานตอนนำเสนอ/ใส่ในเล่มรายงานได้ตรง ๆ
    """
    issues: list[IntegrityIssue] = []
    entries = store.all_entries()
    prev_hash: str | None = None

    for entry in entries:
        if Path(entry.filename).name != entry.filename:
            issues.append(IntegrityIssue(entry.filename, "invalid_filename",
                                         "manifest อ้างไฟล์นอก archive"))
            prev_hash = entry.sha256
            continue
        if entry.prev_sha256 != prev_hash:
            issues.append(IntegrityIssue(
                entry.filename, "chain_broken",
                f"คาดว่า prev_sha256={prev_hash!r} แต่บันทึกไว้เป็น {entry.prev_sha256!r}"))

        path = directory / entry.filename
        if not path.exists() and (directory / (entry.filename + ".gz")).exists():
            # N25: logrotate (delaycompress) บีบอัดไฟล์ที่ผนึกไว้แล้วเปลี่ยนชื่อเป็น .gz -- ไม่ใช่
            # ไฟล์หาย ตรวจ hash ของเนื้อหาข้างในต่อ (sha256_file decompress ให้เอง) ถ้าถูกแก้ก็ยัง
            # ฟ้อง hash_mismatch ได้เหมือนเดิม เดิมฟ้อง missing_file ผิดทุกไฟล์หลังการหมุนรอบที่สอง
            path = directory / (entry.filename + ".gz")
        if entry.deletion_state == "deleted":
            if path.exists():
                issues.append(IntegrityIssue(entry.filename, "unexpected_file",
                                             "ไฟล์ที่บันทึกว่าลบแล้วกลับมาปรากฏ"))
            prev_hash = entry.sha256
            continue
        if entry.deletion_state == "pending":
            issues.append(IntegrityIssue(entry.filename, "pending_delete",
                                         "การลบตามอายุยังไม่เสร็จ ต้องตรวจสอบ"))
        if not path.exists():
            issues.append(IntegrityIssue(entry.filename, "missing_file",
                                         f"ไม่พบไฟล์ {path} — อาจถูกลบทิ้งนอกกระบวนการปกติ"))
        else:
            actual = sha256_file(path)
            if actual != entry.sha256:
                issues.append(IntegrityIssue(
                    entry.filename, "hash_mismatch",
                    f"sha256 ปัจจุบัน {actual[:16]}… ไม่ตรงกับที่บันทึกไว้ {entry.sha256[:16]}… "
                    "— ไฟล์นี้อาจถูกแก้ไขหลังผนึก"))

        prev_hash = entry.sha256

    return issues


_ARCHIVE_DATE = re.compile(r"\.log-(\d{4}-\d{2}-\d{2})(?:\.gz)?$")

# R2-07: issue ที่ prune แก้ต่อเองได้ ไม่ต้องกันไฟล์นั้นไว้ -- pending_delete คือการลบที่ค้างกลางทาง
# (ตัดสินใจลบและบันทึก audit ไปแล้ว) และ missing_file ของรายการ pending ก็คือ unlink สำเร็จแต่
# บันทึก 'deleted' ไม่ทัน ส่วน missing_file ของรายการ active นั้น prune ข้ามอยู่แล้วเพราะไม่มีไฟล์ให้ลบ
_RESUMABLE_KINDS = frozenset({"pending_delete", "missing_file"})


def _archive_path(directory: Path, filename: str) -> Path:
    path = directory / filename
    if not path.exists() and (directory / (filename + ".gz")).exists():
        path = directory / (filename + ".gz")
    return path


def _unlink_archive(path: Path) -> None:
    try:
        subprocess.run(["chattr", "-a", str(path)], capture_output=True, check=False)
    except OSError:
        log.warning("ไม่พบ chattr — ลองลบไฟล์ตามสิทธิ์ของ filesystem")
    path.unlink()


def _finish_pending(store: ManifestStore, entry: ManifestEntry, path: Path) -> bool:
    """R2-07: ทำการลบที่ค้าง (pending) ให้เสร็จ — เดิมไม่มีทางกลับมาทำต่อ เพราะ prune ข้ามรายการ
    ที่ไม่ใช่ active และ main() ไม่เรียก prune เลยเมื่อ verify เจอ pending_delete (deadlock)"""
    if path.exists():
        if sha256_file(path) != entry.sha256:
            log.error("ไม่ลบ %s ต่อ: hash ไม่ตรงกับที่ผนึกไว้ เก็บไว้เป็นหลักฐาน", entry.filename)
            return False
        _unlink_archive(path)
    store.set_deletion(entry.filename, "deleted")
    log.info("ลบ %s ที่ค้างจากรอบก่อนเสร็จแล้ว", entry.filename)
    return True


def prune_archives(store: ManifestStore, directory: Path, retention_days: int,
                   now: datetime | None = None, hold: frozenset[str] | set[str] = frozenset()) -> int:
    """ลบเฉพาะไฟล์ที่ผนึกแล้ว ครบอายุ และ hash ยังตรง; ทำรายการ pending ที่ลบค้างจากรอบก่อนให้เสร็จ

    hold = ชื่อไฟล์ที่ verify_chain ฟ้องปัญหาที่ต้องเก็บไว้เป็นหลักฐาน (เช่น chain_broken) — ข้ามเฉพาะ
    ไฟล์เหล่านั้น ไฟล์อื่นที่ครบอายุยังลบได้ตามปกติ (R2-07) ถ้าไฟล์หนึ่งลบไม่สำเร็จจะไม่หยุดทั้งรอบ
    รายการนั้นจะค้างเป็น pending ให้รอบถัดไปทำต่อ
    """
    if retention_days < 90:
        raise ValueError("LOG_RETENTION_DAYS ต้องไม่น้อยกว่า 90")
    cutoff = (now or datetime.now()).date() - timedelta(days=retention_days)
    count = 0
    for entry in store.all_entries():
        if Path(entry.filename).name != entry.filename:
            log.error("manifest filename ไม่ปลอดภัย: %r", entry.filename)
            continue
        if entry.filename in hold:
            log.warning("ไม่ลบ %s: มีปัญหา integrity ค้างอยู่ เก็บไว้เป็นหลักฐาน", entry.filename)
            continue
        path = _archive_path(directory, entry.filename)
        try:
            if entry.deletion_state == "pending":
                count += _finish_pending(store, entry, path)
                continue
            match = _ARCHIVE_DATE.search(entry.filename)
            if not match or entry.deletion_state != "active" or date.fromisoformat(match[1]) >= cutoff:
                continue
            if entry.sealed_at and entry.sealed_at.date() >= cutoff:
                continue
            if not path.exists() or sha256_file(path) != entry.sha256:
                log.error("ไม่ลบ %s: ไฟล์หายหรือ hash ไม่ตรง", entry.filename)
                continue
            from common import audit
            audit.log_required("raw_log_delete", target=entry.filename,
                               detail=f"sha256={entry.sha256} retention_days={retention_days}")
            store.set_deletion(entry.filename, "pending")
            _unlink_archive(path)
            store.set_deletion(entry.filename, "deleted")
            count += 1
        except Exception:
            log.exception("ลบ %s ไม่สำเร็จ — รอบถัดไปจะลองใหม่", entry.filename)
    return count


def _report_issues(issues: list[IntegrityIssue]) -> None:
    # N21: ต้องบันทึกลง audit_log ในฐานข้อมูลด้วย ไม่ใช่แค่ log ไฟล์ -- ถ้าคนร้ายแก้ไฟล์
    # log ได้ ก็ย่อมลบบรรทัด ERROR ในไฟล์ log ทิ้งได้เหมือนกัน หลักฐานว่า "ตรวจพบการแก้ไข"
    # จึงต้องอยู่คนละที่กับสิ่งที่ถูกแก้ และ ExecStart= ของ cafe-maintenance ใช้ `-` นำหน้า
    # (ยอมให้ fail ได้) exit code 1 จึงถูกกลืน ไม่มีใครรู้เรื่องเลยถ้าไม่บันทึกตรงนี้
    for i in issues:
        log.error("[%s] %s: %s", i.kind, i.filename, i.detail)
        try:
            from common import audit
            audit.log(audit.INTEGRITY_FAILED, target=i.filename,
                     detail=f"kind={i.kind} {i.detail}")
        except Exception:  # DB ล่มก็ยังต้องรายงานผ่าน log ไฟล์ให้ได้ ห้าม crash ทิ้ง
            log.exception("บันทึก audit_log ไม่สำเร็จ — ยังเหลือร่องรอยแค่ใน log ไฟล์เท่านั้น")


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    log_dir = Path(os.environ.get("LOG_DIR", "/var/log/cafe-wifi"))
    archive_dir = log_dir / "archive"
    store = SqlManifestStore()

    sealed = seal_directory(archive_dir, store)
    log.info("ผนึกไฟล์ใหม่ %d ไฟล์", len(sealed))

    issues = verify_chain(store, archive_dir)
    # R2-07: เดิม return 1 ก่อนถึง prune เมื่อเจอ issue ใดก็ได้ -- ไฟล์เดียวที่ hash ไม่ตรง (ต้องเก็บไว้
    # เป็นหลักฐาน) ทำให้ไม่มีไฟล์ไหนถูกลบตามอายุอีกเลยจนดิสก์เต็ม ตอนนี้กันไว้เฉพาะไฟล์ที่มีปัญหา
    hold = {i.filename for i in issues if i.kind not in _RESUMABLE_KINDS}
    prune_failed = False
    try:
        deleted = prune_archives(store, archive_dir,
                                 int(os.environ.get("LOG_RETENTION_DAYS", "180")), hold=hold)
        log.info("ลบ raw log ที่ครบอายุและตรวจ hash แล้ว %d ไฟล์", deleted)
    except Exception:
        log.exception("ลบ raw log ตามอายุไม่สำเร็จ")
        deleted, prune_failed = 0, True
    if deleted:
        # pending ที่ prune ทำต่อจนเสร็จรอบนี้ ไม่ต้องฟ้องซ้ำ
        state = {e.filename: e.deletion_state for e in store.all_entries()}
        issues = [i for i in issues
                  if not (i.kind in _RESUMABLE_KINDS and state.get(i.filename) == "deleted")]

    if issues:
        _report_issues(issues)
        return 1
    if prune_failed:
        return 1
    log.info("ตรวจสาย hash chain ผ่านทั้งหมด (%d ไฟล์)", len(store.all_entries()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
