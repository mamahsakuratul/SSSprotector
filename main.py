#!/usr/bin/env python3
"""
SSSprotector — SenseiSamura-style wallet protection app.
Session timeout, password strength, backup hints, address checks, spend limits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------------------------
# Constants (unique; 137, 619, 2847, 7150)
# ---------------------------------------------------------------------------

APP_NAME = "SSSprotector"
VERSION = "1.2.47"
SESSION_TTL_SECONDS = 137 * 6
MIN_PASSPHRASE_LEN = 12
MAX_RECENT_ADDRESSES = 619
DAILY_SPEND_CAP_WEI = 5_000_000_000_000_000_000
SINGLE_TX_CAP_WEI = 2_000_000_000_000_000_000
ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
CONFIG_DIR_NAME = ".sssprotector"
CONFIG_FILENAME = "config.json"
HISTORY_FILENAME = "history.json"
BACKUP_REMINDER_DAYS = 7
STRENGTH_THRESHOLD = 50
RATE_LIMIT_REQUESTS = 2847 % 100
RATE_LIMIT_WINDOW_SEC = 60

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class SSSConfig:
    session_ttl: int = SESSION_TTL_SECONDS
    min_passphrase_len: int = MIN_PASSPHRASE_LEN
    daily_cap_wei: int = DAILY_SPEND_CAP_WEI
    single_cap_wei: int = SINGLE_TX_CAP_WEI
    backup_reminder_days: int = BACKUP_REMINDER_DAYS
    strength_threshold: int = STRENGTH_THRESHOLD
    config_path: str = ""
    last_backup_reminder: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_ttl": self.session_ttl,
            "min_passphrase_len": self.min_passphrase_len,
            "daily_cap_wei": self.daily_cap_wei,
            "single_cap_wei": self.single_cap_wei,
            "backup_reminder_days": self.backup_reminder_days,
            "strength_threshold": self.strength_threshold,
            "last_backup_reminder": self.last_backup_reminder,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SSSConfig":
        return cls(
            session_ttl=d.get("session_ttl", SESSION_TTL_SECONDS),
            min_passphrase_len=d.get("min_passphrase_len", MIN_PASSPHRASE_LEN),
            daily_cap_wei=int(d.get("daily_cap_wei", DAILY_SPEND_CAP_WEI)),
            single_cap_wei=int(d.get("single_cap_wei", SINGLE_TX_CAP_WEI)),
            backup_reminder_days=d.get("backup_reminder_days", BACKUP_REMINDER_DAYS),
            strength_threshold=d.get("strength_threshold", STRENGTH_THRESHOLD),
            last_backup_reminder=d.get("last_backup_reminder"),
        )


def get_config_dir() -> Path:
    home = Path.home()
    return home / CONFIG_DIR_NAME


def load_config() -> SSSConfig:
    cfg_dir = get_config_dir()
    path = cfg_dir / CONFIG_FILENAME
    if not path.exists():
        return SSSConfig(config_path=str(path))
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        c = SSSConfig.from_dict(d)
        c.config_path = str(path)
        return c
    except Exception:
        return SSSConfig(config_path=str(path))


def save_config(cfg: SSSConfig) -> None:
    cfg_dir = get_config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / CONFIG_FILENAME
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, indent=2)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


@dataclass
class Session:
    session_id: str
    created_at: float
    ttl_seconds: int

    def is_expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return t > self.created_at + self.ttl_seconds


_sessions: Dict[str, Session] = {}


def create_session(ttl: Optional[int] = None) -> str:
    sid = hashlib.sha256(f"{time.time()}{os.urandom(16)}".encode()).hexdigest()[:24]
    cfg = load_config()
    _sessions[sid] = Session(
        session_id=sid,
        created_at=time.time(),
        ttl_seconds=ttl if ttl is not None else cfg.session_ttl,
    )
    return sid


def validate_session(sid: str) -> bool:
    if not sid or sid not in _sessions:
        return False
    s = _sessions[sid]
    if s.is_expired():
        del _sessions[sid]
        return False
    return True


def invalidate_session(sid: str) -> None:
    _sessions.pop(sid, None)


# ---------------------------------------------------------------------------
# Password strength
# ---------------------------------------------------------------------------


def passphrase_strength(passphrase: str) -> int:
    if not passphrase:
        return 0
    score = 0
    if len(passphrase) >= 12:
        score += 25
    if len(passphrase) >= 16:
        score += 15
    if re.search(r"[0-9]", passphrase):
        score += 15
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", passphrase):
        score += 20
    if re.search(r"[A-Z]", passphrase) and re.search(r"[a-z]", passphrase):
        score += 10
    return min(100, score)


def check_passphrase_requirements(passphrase: str, min_len: Optional[int] = None) -> List[str]:
    errors: List[str] = []
    ml = min_len if min_len is not None else MIN_PASSPHRASE_LEN
    if len(passphrase) < ml:
        errors.append(f"Passphrase must be at least {ml} characters")
    if passphrase_strength(passphrase) < STRENGTH_THRESHOLD:
        errors.append("Passphrase strength below threshold (add numbers/symbols)")
    return errors


# ---------------------------------------------------------------------------
# Address validation
# ---------------------------------------------------------------------------


def is_valid_address(addr: str) -> bool:
    return bool(addr and ADDRESS_REGEX.match(addr.strip()))


def normalize_address(addr: str) -> str:
    if not addr:
        return ""
    a = addr.strip()
    if a.startswith("0x"):
        return a
    return "0x" + a


# ---------------------------------------------------------------------------
# Spend limits
# ---------------------------------------------------------------------------


@dataclass
class SpendRecord:
    to_address: str
    amount_wei: int
    timestamp: float


_rolling_spend: List[SpendRecord] = []
_ROLLING_WINDOW_SEC = 86400


def _trim_rolling() -> None:
    now = time.time()
    cutoff = now - _ROLLING_WINDOW_SEC
    global _rolling_spend
    _rolling_spend = [r for r in _rolling_spend if r.timestamp > cutoff]


def record_spend(to_address: str, amount_wei: int) -> None:
    _trim_rolling()
    _rolling_spend.append(SpendRecord(to_address=to_address, amount_wei=amount_wei, timestamp=time.time()))


def rolling_spent_wei() -> int:
    _trim_rolling()
    return sum(r.amount_wei for r in _rolling_spend)


def check_spend_limits(amount_wei: int, cfg: Optional[SSSConfig] = None) -> List[str]:
    errors: List[str] = []
    c = cfg or load_config()
    if amount_wei <= 0:
        errors.append("Amount must be positive")
    if amount_wei > c.single_cap_wei:
        errors.append(f"Amount exceeds single tx cap ({c.single_cap_wei})")
    current = rolling_spent_wei()
    if current + amount_wei > c.daily_cap_wei:
        errors.append(f"Would exceed daily cap ({c.daily_cap_wei}); current rolling: {current}")
    return errors


# ---------------------------------------------------------------------------
# Backup reminder
# ---------------------------------------------------------------------------


def should_show_backup_reminder(cfg: Optional[SSSConfig] = None) -> bool:
    c = cfg or load_config()
    if not c.last_backup_reminder:
        return True
    try:
        last = datetime.fromisoformat(c.last_backup_reminder)
        return (datetime.utcnow() - last).days >= c.backup_reminder_days
    except Exception:
        return True


def mark_backup_reminder_shown(cfg: Optional[SSSConfig] = None) -> None:
    c = cfg or load_config()
    c.last_backup_reminder = datetime.utcnow().isoformat()
    save_config(c)


# ---------------------------------------------------------------------------
# History (recent addresses)
# ---------------------------------------------------------------------------


def get_recent_addresses_path() -> Path:
    return get_config_dir() / HISTORY_FILENAME


def load_recent_addresses() -> List[str]:
    path = get_recent_addresses_path()
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        addrs = data.get("addresses", [])
        return [a for a in addrs if is_valid_address(a)][-MAX_RECENT_ADDRESSES:]
    except Exception:
        return []


def append_recent_address(addr: str) -> None:
    if not is_valid_address(addr):
        return
    addrs = load_recent_addresses()
    addr = normalize_address(addr)
    if addr in addrs:
        addrs.remove(addr)
    addrs.append(addr)
    addrs = addrs[-MAX_RECENT_ADDRESSES:]
    path = get_recent_addresses_path()
    get_config_dir().mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"addresses": addrs}, f, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config()
    print(f"{APP_NAME} v{VERSION}")
    print(f"  Session TTL: {cfg.session_ttl}s")
    print(f"  Daily cap: {cfg.daily_cap_wei} wei")
    print(f"  Single tx cap: {cfg.single_cap_wei} wei")
    print(f"  Rolling spent (24h): {rolling_spent_wei()} wei")
    print(f"  Active sessions: {len(_sessions)}")
    if should_show_backup_reminder(cfg):
        print("  [!] Backup reminder: consider backing up your wallet.")
    return 0


def cmd_strength(args: argparse.Namespace) -> int:
    passphrase = args.passphrase or input("Passphrase: ")
    score = passphrase_strength(passphrase)
    errors = check_passphrase_requirements(passphrase)
    print(f"Strength score: {score}/100")
    if errors:
        for e in errors:
            print(f"  - {e}")
    else:
        print("  OK")
    return 0 if not errors else 1


def cmd_validate_address(args: argparse.Namespace) -> int:
    addr = args.address or input("Address: ")
    addr = normalize_address(addr)
    ok = is_valid_address(addr)
    print(f"Valid: {ok}")
    return 0 if ok else 1


def cmd_check_spend(args: argparse.Namespace) -> int:
    amount = int(args.amount)
    errors = check_spend_limits(amount)
    if not errors:
