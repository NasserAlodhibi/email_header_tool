from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthResult:
    protocol: str
    result: str
    status: str
    colour: str
    explanation: str


class AuthEvaluator:

    def evaluate(
        self,
        spf: Optional[str],
        dkim: Optional[str],
        dmarc: Optional[str],
    ) -> list[AuthResult]:
        return [
            self._evaluate_spf(spf),
            self._evaluate_dkim(dkim),
            self._evaluate_dmarc(dmarc),
        ]

    def _evaluate_spf(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass":      "The sending server is authorised to send email for this domain.",
            "fail":      "The sending server is NOT authorised. Strong indicator of spoofing.",
            "softfail":  "Not authorised but the domain does not enforce rejection. Treat with caution.",
            "neutral":   "The domain has not stated whether this server is authorised.",
            "none":      "No SPF record was found for this domain.",
            "permerror": "Permanent error in the SPF record — it may be misconfigured.",
            "temperror": "Temporary DNS error while checking SPF. Try again later.",
        }
        status_map = {
            "pass":      ("pass", "green"),
            "fail":      ("fail", "red"),
            "softfail":  ("warn", "orange"),
            "neutral":   ("warn", "orange"),
            "none":      ("none", "grey"),
            "permerror": ("fail", "red"),
            "temperror": ("warn", "orange"),
        }
        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        return AuthResult(
            protocol="SPF",
            result=r,
            status=status,
            colour=colour,
            explanation=explanations.get(r, "Unknown SPF result."),
        )

    def _evaluate_dkim(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass":      "The cryptographic signature is valid. The message was not tampered with in transit.",
            "fail":      "The signature is invalid. The email may have been altered or forged.",
            "none":      "No DKIM signature was found on this email.",
            "policy":    "The email was not signed in accordance with the domain's DKIM policy.",
            "neutral":   "The DKIM signature exists but could not be verified.",
            "temperror": "A temporary error occurred during DKIM verification.",
            "permerror": "A permanent error — the DKIM record may be misconfigured.",
        }
        status_map = {
            "pass":      ("pass", "green"),
            "fail":      ("fail", "red"),
            "none":      ("none", "grey"),
            "policy":    ("warn", "orange"),
            "neutral":   ("warn", "orange"),
            "temperror": ("warn", "orange"),
            "permerror": ("fail", "red"),
        }
        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        return AuthResult(
            protocol="DKIM",
            result=r,
            status=status,
            colour=colour,
            explanation=explanations.get(r, "Unknown DKIM result."),
        )

    def _evaluate_dmarc(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass":          "Passed DMARC checks. Domain alignment and authentication are valid.",
            "fail":          "Failed DMARC. The domain's policy may reject or quarantine this message.",
            "none":          "No DMARC record found, or DMARC was not checked.",
            "bestguesspass": "DMARC passed based on a best-guess policy.",
        }
        status_map = {
            "pass":          ("pass", "green"),
            "fail":          ("fail", "red"),
            "none":          ("none", "grey"),
            "bestguesspass": ("warn", "orange"),
        }
        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        return AuthResult(
            protocol="DMARC",
            result=r,
            status=status,
            colour=colour,
            explanation=explanations.get(r, "Unknown DMARC result."),
        )
