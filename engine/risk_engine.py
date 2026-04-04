import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RiskFlag:
    code: str
    severity: str   # "high", "medium", "low"
    title: str
    detail: str


@dataclass
class RiskReport:
    level: str              # "Low", "Medium", "High"
    score: int              # 0–100
    flags: list[RiskFlag] = field(default_factory=list)
    summary: str = ""


class RiskEngine:

    def evaluate(
        self,
        sender: Optional[str],
        reply_to: Optional[str],
        return_path: Optional[str],
        spf: Optional[str],
        dkim: Optional[str],
        dmarc: Optional[str],
        hops: list,
    ) -> RiskReport:

        flags = []

        if spf in ("fail", "permerror"):
            flags.append(RiskFlag(
                code="SPF_FAIL", severity="high",
                title="SPF Failed",
                detail="The sending server is not authorised to send email for this domain. Strong indicator of spoofing.",
            ))
        elif spf == "softfail":
            flags.append(RiskFlag(
                code="SPF_SOFTFAIL", severity="medium",
                title="SPF Soft Fail",
                detail="The sending server is not authorised but the domain does not enforce rejection.",
            ))
        elif spf in (None, "none"):
            flags.append(RiskFlag(
                code="SPF_NONE", severity="low",
                title="No SPF Record",
                detail="No SPF record was found for this domain. Cannot verify sender authorisation.",
            ))

        if dkim in ("fail", "permerror"):
            flags.append(RiskFlag(
                code="DKIM_FAIL", severity="high",
                title="DKIM Failed",
                detail="The email's cryptographic signature is invalid. The message may have been tampered with.",
            ))
        elif dkim in (None, "none"):
            flags.append(RiskFlag(
                code="DKIM_NONE", severity="low",
                title="No DKIM Signature",
                detail="No DKIM signature was found. Cannot verify message integrity.",
            ))

        if dmarc == "fail":
            flags.append(RiskFlag(
                code="DMARC_FAIL", severity="high",
                title="DMARC Failed",
                detail="The email failed DMARC checks. The domain's policy may reject or quarantine this message.",
            ))
        elif dmarc in (None, "none"):
            flags.append(RiskFlag(
                code="DMARC_NONE", severity="low",
                title="No DMARC Record",
                detail="No DMARC policy found. The domain has not defined how to handle authentication failures.",
            ))

        if reply_to and sender:
            sender_domain = self._extract_domain(sender)
            reply_domain  = self._extract_domain(reply_to)
            if sender_domain and reply_domain and sender_domain != reply_domain:
                flags.append(RiskFlag(
                    code="REPLY_TO_MISMATCH", severity="high",
                    title="Reply-To Domain Mismatch",
                    detail=(
                        f"The From domain ({sender_domain}) differs from the Reply-To domain "
                        f"({reply_domain}). Replies would go to a different domain than the sender."
                    ),
                ))

        if return_path and sender:
            sender_domain = self._extract_domain(sender)
            return_domain = self._extract_domain(return_path)
            if sender_domain and return_domain and sender_domain != return_domain:
                flags.append(RiskFlag(
                    code="RETURN_PATH_MISMATCH", severity="medium",
                    title="Return-Path Domain Mismatch",
                    detail=(
                        f"The From domain ({sender_domain}) differs from the Return-Path "
                        f"domain ({return_domain})."
                    ),
                ))

        for hop in hops:
            if getattr(hop, "suspicious", False):
                flags.append(RiskFlag(
                    code="HOP_DELAY", severity="medium",
                    title=f"Suspicious Delay at Hop {hop.index}",
                    detail=(
                        f"Hop {hop.index} took {hop.delay_label} — unusually long and may "
                        "indicate message holding or tampering."
                    ),
                ))

        score   = self._calculate_score(flags)
        level   = self._calculate_level(score)
        summary = self._build_summary(level, flags)

        return RiskReport(level=level, score=score, flags=flags, summary=summary)

    def _extract_domain(self, value: str) -> Optional[str]:
        match = re.search(r"@([\w.\-]+)", value)
        return match.group(1).lower() if match else None

    def _calculate_score(self, flags: list[RiskFlag]) -> int:
        weights = {"high": 35, "medium": 15, "low": 5}
        return min(sum(weights.get(f.severity, 0) for f in flags), 100)

    def _calculate_level(self, score: int) -> str:
        if score >= 50:
            return "High"
        if score >= 20:
            return "Medium"
        return "Low"

    def _build_summary(self, level: str, flags: list[RiskFlag]) -> str:
        if not flags:
            return "No suspicious indicators detected. This email appears legitimate."
        count = len(flags)
        high  = sum(1 for f in flags if f.severity == "high")
        if level == "High":
            return (
                f"{count} suspicious indicator(s) detected ({high} high severity). "
                "This email shows strong signs of phishing or spoofing."
            )
        if level == "Medium":
            return (
                f"{count} suspicious indicator(s) detected. "
                "This email has some concerning properties and should be treated with caution."
            )
        return (
            f"{count} minor indicator(s) detected. "
            "This email is likely legitimate but has some missing security records."
        )
