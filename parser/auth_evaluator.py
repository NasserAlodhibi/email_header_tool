from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthResult:
    """Holds the evaluated result for a single auth protocol."""
    protocol: str           # e.g. "SPF"
    result: str             # e.g. "fail"
    status: str             # "pass", "fail", "warn", "none"
    colour: str             # "green", "red", "orange", "grey"
    explanation: str        # plain-English description


class AuthEvaluator:
    """
    Takes raw SPF, DKIM, DMARC strings from the parser
    and returns structured AuthResult objects.
    """

    def evaluate(
        self,
        spf: Optional[str],
        dkim: Optional[str],
        dmarc: Optional[str]
    ) -> list[AuthResult]:
        return [
            self._evaluate_spf(spf),
            self._evaluate_dkim(dkim),
            self._evaluate_dmarc(dmarc),
        ]

    # ── SPF ───────────────────────────────────────────────────────

    def _evaluate_spf(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass": "The sending server is authorised to send email for this domain.",
            "fail": "The sending server is NOT authorised. This is a strong indicator of spoofing.",
            "softfail": "The sending server is not authorised but the domain is not enforcing rejection. Treat with caution.",
            "neutral": "The domain has not stated whether the server is authorised or not.",
            "none": "No SPF record was found for this domain.",
            "permerror": "There is a permanent error in the SPF record — it may be misconfigured.",
            "temperror": "A temporary DNS error occurred while checking SPF. Try again later.",
        }

        status_map = {
            "pass": ("pass", "green"),
            "fail": ("fail", "red"),
            "softfail": ("warn", "orange"),
            "neutral": ("warn", "orange"),
            "none": ("none", "grey"),
            "permerror": ("fail", "red"),
            "temperror": ("warn", "orange"),
        }

        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        explanation = explanations.get(r, "Unknown SPF result.")

        return AuthResult(
            protocol="SPF",
            result=r,
            status=status,
            colour=colour,
            explanation=explanation,
        )

    # ── DKIM ──────────────────────────────────────────────────────

    def _evaluate_dkim(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass": "The email's cryptographic signature is valid. The message was not tampered with in transit.",
            "fail": "The cryptographic signature is invalid. The email may have been altered or forged.",
            "none": "No DKIM signature was found on this email.",
            "policy": "The email was not signed in accordance with the domain's DKIM policy.",
            "neutral": "The DKIM signature exists but could not be verified.",
            "temperror": "A temporary error occurred during DKIM verification.",
            "permerror": "A permanent error occurred — the DKIM record may be misconfigured.",
        }

        status_map = {
            "pass": ("pass", "green"),
            "fail": ("fail", "red"),
            "none": ("none", "grey"),
            "policy": ("warn", "orange"),
            "neutral": ("warn", "orange"),
            "temperror": ("warn", "orange"),
            "permerror": ("fail", "red"),
        }

        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        explanation = explanations.get(r, "Unknown DKIM result.")

        return AuthResult(
            protocol="DKIM",
            result=r,
            status=status,
            colour=colour,
            explanation=explanation,
        )

    # ── DMARC ─────────────────────────────────────────────────────

    def _evaluate_dmarc(self, result: Optional[str]) -> AuthResult:
        explanations = {
            "pass": "The email passed DMARC checks. Both the domain alignment and authentication are valid.",
            "fail": "The email failed DMARC. The domain's policy may reject or quarantine this message.",
            "none": "No DMARC record was found, or DMARC was not checked.",
            "bestguesspass": "DMARC passed based on a best-guess policy.",
        }

        status_map = {
            "pass": ("pass", "green"),
            "fail": ("fail", "red"),
            "none": ("none", "grey"),
            "bestguesspass": ("warn", "orange"),
        }

        r = (result or "none").lower()
        status, colour = status_map.get(r, ("none", "grey"))
        explanation = explanations.get(r, "Unknown DMARC result.")

        return AuthResult(
            protocol="DMARC",
            result=r,
            status=status,
            colour=colour,
            explanation=explanation,
        )