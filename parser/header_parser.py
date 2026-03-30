import email
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedHeader:
    """Holds all extracted fields from an email header."""

    # Basic fields
    subject: Optional[str] = None
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None

    # Authentication
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    auth_results_raw: Optional[str] = None

    # Routing
    received_hops: list = field(default_factory=list)
    originating_ip: Optional[str] = None

    # Raw
    raw_headers: dict = field(default_factory=dict)


class HeaderParser:
    """Parses a raw email header string and returns a ParsedHeader object."""

    def parse(self, raw_header: str) -> ParsedHeader:
        result = ParsedHeader()

        # Use Python's built-in email parser to read the header
        msg = email.message_from_string(raw_header)

        # ── Basic fields ──────────────────────────────────────────
        result.subject = self._clean(msg.get("Subject"))
        result.sender = self._clean(msg.get("From"))
        result.reply_to = self._clean(msg.get("Reply-To"))
        result.date = self._clean(msg.get("Date"))
        result.message_id = self._clean(msg.get("Message-ID"))
        result.return_path = self._clean(msg.get("Return-Path"))

        # ── Authentication ────────────────────────────────────────
        auth_results = self._clean(msg.get("Authentication-Results"))
        result.auth_results_raw = auth_results
        if auth_results:
            result.spf = self._extract_auth(auth_results, "spf")
            result.dkim = self._extract_auth(auth_results, "dkim")
            result.dmarc = self._extract_auth(auth_results, "dmarc")

        # Fallback: check Received-SPF header if not found above
        if not result.spf:
            received_spf = self._clean(msg.get("Received-SPF"))
            if received_spf:
                result.spf = received_spf.split()[0].lower()

        # ── Originating IP ────────────────────────────────────────
        for key in ["X-Originating-IP", "X-Sender-IP", "X-Source-IP"]:
            val = self._clean(msg.get(key))
            if val:
                result.originating_ip = val
                break

        # ── Received hops ─────────────────────────────────────────
        received_headers = msg.get_all("Received") or []
        result.received_hops = self._parse_hops(received_headers)

        # ── Store all raw headers as a dict ───────────────────────
        result.raw_headers = dict(msg.items())

        return result

    # ── Helper methods ────────────────────────────────────────────

    def _clean(self, value: Optional[str]) -> Optional[str]:
        """Strip whitespace and newlines from a header value."""
        if value is None:
            return None
        return " ".join(value.split())

    def _extract_auth(self, auth_string: str, protocol: str) -> Optional[str]:
        """
        Pull the result for a given protocol (spf, dkim, dmarc)
        from the Authentication-Results header.
        """
        pattern = rf"{protocol}=(\w+)"
        match = re.search(pattern, auth_string, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _parse_hops(self, received_headers: list) -> list:
        """
        Parse each Received header into a structured dict.
        Received headers are in reverse order (newest first),
        so we reverse them to get chronological order.
        """
        hops = []
        for raw in received_headers:
            hop = {"raw": raw, "from": None, "by": None, "timestamp": None}

            # Extract 'from' server
            from_match = re.search(r"from\s+(\S+)", raw, re.IGNORECASE)
            if from_match:
                hop["from"] = from_match.group(1)

            # Extract 'by' server
            by_match = re.search(r"by\s+(\S+)", raw, re.IGNORECASE)
            if by_match:
                hop["by"] = by_match.group(1)

            # Extract timestamp (everything after the semicolon)
            time_match = re.search(r";\s*(.+)$", raw, re.IGNORECASE)
            if time_match:
                hop["timestamp"] = time_match.group(1).strip()

            hops.append(hop)

        # Reverse so earliest hop is first
        hops.reverse()
        return hops