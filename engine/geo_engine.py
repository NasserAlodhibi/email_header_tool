import re
import json
from urllib.request import urlopen
from urllib.error import URLError
from dataclasses import dataclass
from typing import Optional


@dataclass
class GeoResult:
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    error: Optional[str] = None

    @property
    def location(self) -> str:
        parts = [p for p in [self.city, self.country] if p]
        return ", ".join(parts) if parts else "Unknown"


class GeoEngine:

    def lookup(self, ip: str) -> GeoResult:
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,org,lat,lon,query"
            with urlopen(url, timeout=4) as response:
                data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return GeoResult(
                    ip=ip,
                    country=data.get("country"),
                    city=data.get("city"),
                    org=data.get("org"),
                    lat=data.get("lat"),
                    lon=data.get("lon"),
                )
            return GeoResult(ip=ip, error="Lookup failed")
        except URLError:
            return GeoResult(ip=ip, error="Network unavailable")
        except Exception as e:
            return GeoResult(ip=ip, error=str(e))

    def extract_ip(self, raw_hop: Optional[str]) -> Optional[str]:
        """Return the first public IP found in a raw Received header string."""
        if not raw_hop:
            return None
        for match in re.finditer(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', raw_hop):
            ip = match.group(1)
            if not self._is_private(ip):
                return ip
        return None

    def _is_private(self, ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
        except ValueError:
            return True
        o = parts[0]
        return (
            o == 10 or
            o == 127 or
            (o == 172 and 16 <= parts[1] <= 31) or
            (o == 192 and parts[1] == 168)
        )
