import email
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedHeader:
    subject: Optional[str] = None
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None

    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    auth_results_raw: Optional[str] = None

    received_hops: list = field(default_factory=list)
    originating_ip: Optional[str] = None

    raw_headers: dict = field(default_factory=dict)


class HeaderParser:

    def parse(self, raw_header: str) -> ParsedHeader:
        result = ParsedHeader()
        msg = email.message_from_string(raw_header)

        result.subject    = self._clean(msg.get("Subject"))
        result.sender     = self._clean(msg.get("From"))
        result.reply_to   = self._clean(msg.get("Reply-To"))
        result.date       = self._clean(msg.get("Date"))
        result.message_id = self._clean(msg.get("Message-ID"))
        result.return_path = self._clean(msg.get("Return-Path"))

        auth_results = self._clean(msg.get("Authentication-Results"))
        result.auth_results_raw = auth_results
        if auth_results:
            result.spf  = self._extract_auth(auth_results, "spf")
            result.dkim = self._extract_auth(auth_results, "dkim")
            result.dmarc = self._extract_auth(auth_results, "dmarc")

        # Fall back to the dedicated Received-SPF header if not found above
        if not result.spf:
            received_spf = self._clean(msg.get("Received-SPF"))
            if received_spf:
                result.spf = received_spf.split()[0].lower()

        for key in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
            val = self._clean(msg.get(key))
            if val:
                result.originating_ip = val
                break

        received_headers = msg.get_all("Received") or []
        result.received_hops = self._parse_hops(received_headers)

        result.raw_headers = dict(msg.items())
        return result

    def _clean(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return " ".join(value.split())

    def _extract_auth(self, auth_string: str, protocol: str) -> Optional[str]:
        match = re.search(rf"{protocol}=(\w+)", auth_string, re.IGNORECASE)
        return match.group(1).lower() if match else None

    def _parse_hops(self, received_headers: list) -> list:
        # Received headers arrive newest-first; reverse for chronological order
        hops = []
        for raw in received_headers:
            hop = {"raw": raw, "from": None, "by": None, "timestamp": None}

            from_match = re.search(r"from\s+(\S+)", raw, re.IGNORECASE)
            if from_match:
                hop["from"] = from_match.group(1)

            by_match = re.search(r"by\s+(\S+)", raw, re.IGNORECASE)
            if by_match:
                hop["by"] = by_match.group(1)

            time_match = re.search(r";\s*(.+)$", raw, re.IGNORECASE)
            if time_match:
                hop["timestamp"] = time_match.group(1).strip()

            hops.append(hop)

        hops.reverse()
        return hops
