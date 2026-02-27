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


