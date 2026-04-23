from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from dateutil import tz


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime
    timezone: str


def compute_window(timezone: str, window_hours: int) -> TimeWindow:
    zone = tz.gettz(timezone)
    if zone is None:
        raise ValueError(f"invalid timezone: {timezone}")
    end = datetime.now(tz=zone)
    start = end - timedelta(hours=window_hours)
    return TimeWindow(start=start, end=end, timezone=timezone)


def isoformat_z(dt: datetime) -> str:
    return dt.isoformat()


def fmt_compact(dt: datetime) -> str:
    return dt.strftime("%Y%m%d_%H%M%S")

