from dataclasses import dataclass
from typing import Optional
from email.utils import parsedate_to_datetime
import datetime


@dataclass
class Hop:
    index: int
    from_server: Optional[str]
    by_server: Optional[str]
    timestamp: Optional[datetime.datetime]
    timestamp_raw: Optional[str]
    delay_seconds: Optional[int]
    delay_label: Optional[str]
    suspicious: bool = False
    raw: Optional[str] = None


class HopAnalyser:

    SUSPICIOUS_DELAY_SECONDS = 1800  # 30 minutes

    def analyse(self, raw_hops: list) -> list[Hop]:
        hops = []

        for i, raw in enumerate(raw_hops):
            timestamp = self._parse_timestamp(raw.get("timestamp"))
            hop = Hop(
                index=i + 1,
                from_server=raw.get("from"),
                by_server=raw.get("by"),
                timestamp=timestamp,
                timestamp_raw=raw.get("timestamp"),
                delay_seconds=None,
                delay_label=None,
                suspicious=False,
                raw=raw.get("raw"),
            )
            hops.append(hop)

        for i in range(1, len(hops)):
            prev = hops[i - 1]
            curr = hops[i]
            if prev.timestamp and curr.timestamp:
                delta = curr.timestamp - prev.timestamp
                # Clock skew between servers can produce small negatives; clamp to zero
                seconds = max(int(delta.total_seconds()), 0)
                curr.delay_seconds = seconds
                curr.delay_label   = self._format_delay(seconds)
                curr.suspicious    = seconds >= self.SUSPICIOUS_DELAY_SECONDS

        return hops

    def _parse_timestamp(self, raw: Optional[str]) -> Optional[datetime.datetime]:
        if not raw:
            return None
        try:
            return parsedate_to_datetime(raw.strip())
        except Exception:
            return None

    def _format_delay(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds} sec"
        minutes = seconds // 60
        remaining = seconds % 60
        if minutes < 60:
            return f"{minutes} min {remaining} sec"
        hours = minutes // 60
        return f"{hours} hr {minutes % 60} min"
