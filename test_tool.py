import unittest
from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser
from engine.risk_engine import RiskEngine

# ── Shared sample headers ─────────────────────────────────────────

PHISHING_HEADER = """From: attacker@evil.com
Reply-To: real@gmail.com
Subject: You won a prize!
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <abc123@evil.com>
Return-Path: <bounce@evil.com>
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of attacker@evil.com does not designate)
       dkim=fail header.i=@evil.com
       dmarc=fail
Received: from mail.evil.com (mail.evil.com [192.168.1.1])
        by mx.google.com with ESMTP; Mon, 01 Jan 2024 10:00:01 +0000
Received: from [10.0.0.1] (unknown)
        by mail.evil.com with SMTP; Mon, 01 Jan 2024 09:59:55 +0000
"""

LEGITIMATE_HEADER = """From: john.smith@gmail.com
Reply-To: john.smith@gmail.com
Subject: Project update for this week
Date: Tue, 16 Jan 2024 09:15:00 +0000
Message-ID: <CABxyz123@mail.gmail.com>
Return-Path: <john.smith@gmail.com>
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of john.smith@gmail.com designates 209.85.220.41)
       dkim=pass header.i=@gmail.com
       dmarc=pass
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.google.com with SMTPS; Tue, 16 Jan 2024 09:15:03 +0000
Received: from [192.168.1.105] (unknown)
        by mail-sor-f41.google.com with SMTP; Tue, 16 Jan 2024 09:14:58 +0000
"""

SPOOFED_HEADER = """From: ceo@legitimate-company.com
Reply-To: ceo@legitimate-company.com
Subject: Urgent wire transfer needed
Date: Wed, 17 Jan 2024 11:00:00 +0000
Message-ID: <spoof789@fakeserver.net>
Return-Path: <noreply@fakeserver.net>
Authentication-Results: mx.victim-company.com;
       spf=softfail (domain of ceo@legitimate-company.com does not designate 91.108.4.1)
       dkim=none
       dmarc=fail (p=QUARANTINE)
Received: from fakeserver.net (fakeserver.net [91.108.4.1])
        by mx.victim-company.com with ESMTP; Wed, 17 Jan 2024 11:00:06 +0000
Received: from [172.16.0.1] (unknown)
        by fakeserver.net with SMTP; Wed, 17 Jan 2024 10:52:00 +0000
"""

BEC_HEADER = """From: cfo@acme-corp.com
Reply-To: payments@acme-c0rp.com
Subject: URGENT: Invoice #INV-2024-0892 Payment Required
Date: Thu, 18 Jan 2024 08:45:00 +0000
Message-ID: <20240118084500.bec001@fakeserver.net>
Return-Path: <bounce@acme-c0rp.com>
Authentication-Results: mx.victim-company.com;
       spf=softfail (domain of cfo@acme-corp.com does not designate 91.108.56.12)
       dkim=none
       dmarc=fail (p=QUARANTINE)
Received: from mail.acme-c0rp.com (acme-c0rp.com [91.108.56.12])
        by mx.victim-company.com with ESMTP; Thu, 18 Jan 2024 08:45:06 +0000
Received: from [10.20.30.1] (unknown)
        by mail.acme-c0rp.com with SMTP; Thu, 18 Jan 2024 08:44:50 +0000
"""

FAKE_PASSWORD_RESET_HEADER = """From: security@micros0ft-account.com
Reply-To: noreply@micros0ft-account.com
Subject: Action Required: Verify your Microsoft account
Date: Fri, 19 Jan 2024 14:22:00 +0000
Message-ID: <20240119142200.msft001@micros0ft-account.com>
Return-Path: <bounce@micros0ft-account.com>
Authentication-Results: mx.victim.com;
       spf=fail (domain of security@micros0ft-account.com does not designate 185.234.218.45)
       dkim=fail header.i=@micros0ft-account.com
       dmarc=fail (p=REJECT)
Received: from phish-infra.ru (phish-infra.ru [185.234.218.45])
        by mx.victim.com with ESMTP; Fri, 19 Jan 2024 14:22:05 +0000
Received: from [172.16.0.5] (unknown)
        by phish-infra.ru with SMTP; Fri, 19 Jan 2024 14:21:48 +0000
Received: from [10.0.5.1] (unknown)
        by internal.phish-infra.ru with SMTP; Fri, 19 Jan 2024 13:55:00 +0000
"""

LEGITIMATE_OUTLOOK_HEADER = """From: jane.doe@contoso.com
Reply-To: jane.doe@contoso.com
Subject: Q1 Planning Meeting - Agenda
Date: Mon, 22 Jan 2024 09:30:00 +0000
Message-ID: <LO2P265MB4392.GBRP265.PROD.OUTLOOK.COM>
Return-Path: <jane.doe@contoso.com>
Authentication-Results: mx.contoso.com;
       spf=pass (protection.outlook.com: domain of contoso.com designates 40.107.220.50)
       dkim=pass header.d=contoso.com header.s=selector1-contoso-com
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=contoso.com
Received: from GBR01-LO2-obe.outbound.protection.outlook.com ([40.107.220.50])
        by mx.contoso.com with HTTPS; Mon, 22 Jan 2024 09:30:04 +0000
Received: from LO2P265MB4392.GBRP265.PROD.OUTLOOK.COM ([2603:10a6:600:1ab::10])
        by LO2P265CA0012.outlook.office365.com; Mon, 22 Jan 2024 09:30:01 +0000
Received: from [192.168.10.22] (unknown)
        by LO2P265MB4392.GBRP265.PROD.OUTLOOK.COM; Mon, 22 Jan 2024 09:29:58 +0000
"""

NEWSLETTER_HEADER = """From: newsletter@mailchimp-sends.com
Reply-To: newsletter@real-company.com
Subject: Your weekly digest is ready
Date: Tue, 23 Jan 2024 07:00:00 +0000
Message-ID: <abc123def456.newsletter@mailchimp-sends.com>
Return-Path: <bounce-newsletter@mailchimp-sends.com>
Authentication-Results: mx.recipient.com;
       spf=pass (domain of mailchimp-sends.com designates 198.2.136.64)
       dkim=pass header.i=@mailchimp-sends.com
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mailchimp-sends.com
Received: from mail136-64.atl31.rsgsv.net (mail136-64.atl31.rsgsv.net [198.2.136.64])
        by mx.recipient.com with ESMTPS; Tue, 23 Jan 2024 07:00:03 +0000
Received: from [10.130.0.200] (unknown)
        by mail136-64.atl31.rsgsv.net with ESMTP; Tue, 23 Jan 2024 07:00:01 +0000
"""

MALWARE_HEADER = """From: hr@payroll-notifications.net
Reply-To: hr@payroll-notifications.net
Subject: Your payslip for January 2024 is ready
Date: Wed, 24 Jan 2024 11:15:00 +0000
Message-ID: <20240124111500.mal001@payroll-notifications.net>
Return-Path: <noreply@payroll-notifications.net>
Authentication-Results: mx.victim-corp.com;
       spf=fail (domain of hr@payroll-notifications.net does not designate 193.32.160.44)
       dkim=none
       dmarc=fail (p=NONE sp=NONE dis=NONE)
Received: from bulk-mailer.xyz (bulk-mailer.xyz [193.32.160.44])
        by mx.victim-corp.com with ESMTP; Wed, 24 Jan 2024 11:15:07 +0000
Received: from [10.8.0.55] (unknown)
        by bulk-mailer.xyz with SMTP; Wed, 24 Jan 2024 11:14:40 +0000
Received: from [172.20.0.1] (unknown)
        by internal.bulk-mailer.xyz with SMTP; Wed, 24 Jan 2024 10:45:00 +0000
"""

MINIMAL_HEADER = """From: someone@example.com
Subject: Hello
Date: Wed, 17 Jan 2024 12:00:00 +0000
"""

EMPTY_HEADER = ""


# ══════════════════════════════════════════════════════════════════
#  UNIT TESTS — HeaderParser
# ══════════════════════════════════════════════════════════════════

class TestHeaderParser(unittest.TestCase):

    def setUp(self):
        self.parser = HeaderParser()

    def test_UT01_parse_from_field(self):
        """UT-01: From field is extracted correctly."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.sender, "attacker@evil.com")

    def test_UT02_parse_reply_to_field(self):
        """UT-02: Reply-To field is extracted correctly."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.reply_to, "real@gmail.com")

    def test_UT03_parse_subject_field(self):
        """UT-03: Subject field is extracted correctly."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.subject, "You won a prize!")

    def test_UT04_parse_return_path_field(self):
        """UT-04: Return-Path field is extracted correctly."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertIn("bounce@evil.com", result.return_path)

    def test_UT05_missing_optional_field_returns_none(self):
        """UT-05: Missing optional field returns None, not an error."""
        result = self.parser.parse(MINIMAL_HEADER)
        self.assertIsNone(result.reply_to)

    def test_parse_spf_from_auth_results(self):
        """SPF result is extracted from Authentication-Results header."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.spf, "fail")

    def test_parse_dkim_from_auth_results(self):
        """DKIM result is extracted from Authentication-Results header."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.dkim, "fail")

    def test_parse_dmarc_from_auth_results(self):
        """DMARC result is extracted from Authentication-Results header."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(result.dmarc, "fail")

    def test_parse_received_hops_count(self):
        """Two Received headers produce two hops."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertEqual(len(result.received_hops), 2)

    def test_parse_empty_header_does_not_crash(self):
        """Empty input returns a ParsedHeader with all None values."""
        result = self.parser.parse(EMPTY_HEADER)
        self.assertIsNone(result.sender)
        self.assertIsNone(result.subject)
        self.assertEqual(result.received_hops, [])

    def test_parse_legitimate_spf_pass(self):
        """Legitimate header returns SPF pass."""
        result = self.parser.parse(LEGITIMATE_HEADER)
        self.assertEqual(result.spf, "pass")

    def test_parse_raw_headers_dict_populated(self):
        """raw_headers dict is populated with all fields."""
        result = self.parser.parse(PHISHING_HEADER)
        self.assertIn("From", result.raw_headers)
        self.assertIn("Subject", result.raw_headers)

    def test_parse_three_hops_fake_password_reset(self):
        """Fake password reset header has three hops."""
        result = self.parser.parse(FAKE_PASSWORD_RESET_HEADER)
        self.assertEqual(len(result.received_hops), 3)

    def test_parse_three_hops_malware(self):
        """Malware delivery header has three hops."""
        result = self.parser.parse(MALWARE_HEADER)
        self.assertEqual(len(result.received_hops), 3)

    def test_parse_outlook_dmarc_pass(self):
        """Legitimate Outlook header returns DMARC pass."""
        result = self.parser.parse(LEGITIMATE_OUTLOOK_HEADER)
        self.assertEqual(result.dmarc, "pass")

    def test_parse_newsletter_spf_pass(self):
        """Newsletter header returns SPF pass."""
        result = self.parser.parse(NEWSLETTER_HEADER)
        self.assertEqual(result.spf, "pass")

    def test_parse_bec_spf_softfail(self):
        """BEC header returns SPF softfail."""
        result = self.parser.parse(BEC_HEADER)
        self.assertEqual(result.spf, "softfail")


# ══════════════════════════════════════════════════════════════════
#  UNIT TESTS — AuthEvaluator
# ══════════════════════════════════════════════════════════════════

class TestAuthEvaluator(unittest.TestCase):

    def setUp(self):
        self.evaluator = AuthEvaluator()

    def test_UT06_spf_fail_returns_red(self):
        """UT-06: SPF fail produces status=fail and colour=red."""
        results = self.evaluator.evaluate("fail", "pass", "pass")
        spf = results[0]
        self.assertEqual(spf.status, "fail")
        self.assertEqual(spf.colour, "red")

    def test_UT07_spf_pass_returns_green(self):
        """UT-07: SPF pass produces status=pass and colour=green."""
        results = self.evaluator.evaluate("pass", "pass", "pass")
        spf = results[0]
        self.assertEqual(spf.status, "pass")
        self.assertEqual(spf.colour, "green")

    def test_UT08_dkim_pass_returns_green(self):
        """UT-08: DKIM pass produces status=pass and colour=green."""
        results = self.evaluator.evaluate("pass", "pass", "pass")
        dkim = results[1]
        self.assertEqual(dkim.status, "pass")
        self.assertEqual(dkim.colour, "green")

    def test_UT09_dmarc_fail_returns_red(self):
        """UT-09: DMARC fail produces status=fail and colour=red."""
        results = self.evaluator.evaluate("pass", "pass", "fail")
        dmarc = results[2]
        self.assertEqual(dmarc.status, "fail")
        self.assertEqual(dmarc.colour, "red")

    def test_spf_softfail_returns_orange(self):
        """SPF softfail produces status=warn and colour=orange."""
        results = self.evaluator.evaluate("softfail", None, None)
        spf = results[0]
        self.assertEqual(spf.status, "warn")
        self.assertEqual(spf.colour, "orange")

    def test_none_values_return_grey(self):
        """None auth values produce status=none and colour=grey."""
        results = self.evaluator.evaluate(None, None, None)
        for auth in results:
            self.assertEqual(auth.status, "none")
            self.assertEqual(auth.colour, "grey")

    def test_evaluate_returns_three_results(self):
        """evaluate() always returns exactly 3 AuthResult objects."""
        results = self.evaluator.evaluate("pass", "pass", "pass")
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].protocol, "SPF")
        self.assertEqual(results[1].protocol, "DKIM")
        self.assertEqual(results[2].protocol, "DMARC")

    def test_explanation_is_not_empty(self):
        """Every auth result includes a non-empty explanation string."""
        results = self.evaluator.evaluate("fail", "none", "pass")
        for auth in results:
            self.assertIsNotNone(auth.explanation)
            self.assertGreater(len(auth.explanation), 0)


# ══════════════════════════════════════════════════════════════════
#  UNIT TESTS — HopAnalyser
# ══════════════════════════════════════════════════════════════════

class TestHopAnalyser(unittest.TestCase):

    def setUp(self):
        self.parser = HeaderParser()
        self.analyser = HopAnalyser()

    def test_UT10_hop_delay_calculation(self):
        """UT-10: Delay between hops is calculated correctly (6 seconds)."""
        parsed = self.parser.parse(PHISHING_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertEqual(hops[1].delay_seconds, 6)
        self.assertEqual(hops[1].delay_label, "6 sec")

    def test_UT11_hop_chronological_order(self):
        """UT-11: Hops are returned in chronological order (oldest first)."""
        parsed = self.parser.parse(PHISHING_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertEqual(hops[0].index, 1)
        self.assertEqual(hops[1].index, 2)
        self.assertIn("google", hops[1].by_server.lower())

    def test_UT12_suspicious_delay_flagged(self):
        """UT-12: A delay over 30 minutes is flagged as suspicious."""
        raw_hops = [
            {
                "raw": "raw1",
                "from": "server1.com",
                "by": "server2.com",
                "timestamp": "Mon, 01 Jan 2024 09:00:00 +0000",
            },
            {
                "raw": "raw2",
                "from": "server2.com",
                "by": "server3.com",
                "timestamp": "Mon, 01 Jan 2024 09:35:00 +0000",
            },
        ]
        hops = self.analyser.analyse(raw_hops)
        self.assertTrue(hops[1].suspicious)

    def test_first_hop_has_no_delay(self):
        """First hop always has delay_seconds = None (no previous hop)."""
        parsed = self.parser.parse(PHISHING_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertIsNone(hops[0].delay_seconds)

    def test_no_hops_returns_empty_list(self):
        """Header with no Received fields returns an empty hop list."""
        parsed = self.parser.parse(MINIMAL_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertEqual(hops, [])

    def test_three_hops_parsed_correctly(self):
        """Malware header with three Received fields produces three hops."""
        parsed = self.parser.parse(MALWARE_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertEqual(len(hops), 3)

    def test_three_hops_fake_password_reset(self):
        """Fake password reset header produces three hops."""
        parsed = self.parser.parse(FAKE_PASSWORD_RESET_HEADER)
        hops = self.analyser.analyse(parsed.received_hops)
        self.assertEqual(len(hops), 3)


# ══════════════════════════════════════════════════════════════════
#  INTEGRATION TESTS — Full Pipeline (all 8 samples)
# ══════════════════════════════════════════════════════════════════

class TestFullPipeline(unittest.TestCase):

    def _run(self, header):
        parsed = HeaderParser().parse(header)
        auth = AuthEvaluator().evaluate(parsed.spf, parsed.dkim, parsed.dmarc)
        hops = HopAnalyser().analyse(parsed.received_hops)
        report = RiskEngine().evaluate(
            sender=parsed.sender,
            reply_to=parsed.reply_to,
            return_path=parsed.return_path,
            spf=parsed.spf,
            dkim=parsed.dkim,
            dmarc=parsed.dmarc,
            hops=hops,
        )
        return parsed, auth, hops, report

    def test_IT01_phishing_risk_high(self):
        """IT-01: Phishing header produces High risk level."""
        _, _, _, report = self._run(PHISHING_HEADER)
        self.assertEqual(report.level, "High")

    def test_IT02_legitimate_risk_low(self):
        """IT-02: Legitimate Gmail header produces Low risk with no flags."""
        _, _, _, report = self._run(LEGITIMATE_HEADER)
        self.assertEqual(report.level, "Low")
        self.assertEqual(len(report.flags), 0)

    def test_IT03_spoofed_risk_high(self):
        """IT-03: Spoofed CEO fraud header produces High risk."""
        _, _, _, report = self._run(SPOOFED_HEADER)
        self.assertEqual(report.level, "High")

    def test_IT04_bec_risk_high(self):
        """IT-04: BEC fake invoice header produces High risk."""
        _, _, _, report = self._run(BEC_HEADER)
        self.assertEqual(report.level, "High")

    def test_IT05_bec_reply_to_mismatch_flagged(self):
        """IT-05: BEC header flags Reply-To domain mismatch."""
        _, _, _, report = self._run(BEC_HEADER)
        flag_codes = [f.code for f in report.flags]
        self.assertIn("REPLY_TO_MISMATCH", flag_codes)

    def test_IT06_fake_password_reset_risk_high(self):
        """IT-06: Fake password reset header produces High risk."""
        _, _, _, report = self._run(FAKE_PASSWORD_RESET_HEADER)
        self.assertEqual(report.level, "High")

    def test_IT07_fake_password_reset_spf_fail_flagged(self):
        """IT-07: Fake password reset header flags SPF failure."""
        _, _, _, report = self._run(FAKE_PASSWORD_RESET_HEADER)
        flag_codes = [f.code for f in report.flags]
        self.assertIn("SPF_FAIL", flag_codes)

    def test_IT08_legitimate_outlook_risk_low(self):
        """IT-08: Legitimate Outlook/M365 header produces Low risk."""
        _, _, _, report = self._run(LEGITIMATE_OUTLOOK_HEADER)
        self.assertEqual(report.level, "Low")
        self.assertEqual(len(report.flags), 0)

    def test_IT09_newsletter_risk_low(self):
        """IT-09: Legitimate newsletter header produces Low risk."""
        _, _, _, report = self._run(NEWSLETTER_HEADER)
        self.assertEqual(report.level, "Low")

    def test_IT10_malware_risk_high(self):
        """IT-10: Malware delivery header produces High risk."""
        _, _, _, report = self._run(MALWARE_HEADER)
        self.assertEqual(report.level, "High")

    def test_IT11_malware_spf_fail_flagged(self):
        """IT-11: Malware delivery header flags SPF failure."""
        _, _, _, report = self._run(MALWARE_HEADER)
        flag_codes = [f.code for f in report.flags]
        self.assertIn("SPF_FAIL", flag_codes)

    def test_IT12_phishing_score_is_high(self):
        """IT-12: Phishing header risk score is 50 or above."""
        _, _, _, report = self._run(PHISHING_HEADER)
        self.assertGreaterEqual(report.score, 50)

    def test_IT13_hop_chart_builds_without_error(self):
        """IT-13: Hop chart builds from parsed hops without error."""
        from visualisation.hop_chart import build_hop_chart
        parsed = HeaderParser().parse(PHISHING_HEADER)
        hops = HopAnalyser().analyse(parsed.received_hops)
        chart = build_hop_chart(hops)
        self.assertIsNotNone(chart)

    def test_IT14_empty_header_does_not_crash_pipeline(self):
        """IT-14: Empty header runs through full pipeline without crashing."""
        try:
            self._run(EMPTY_HEADER)
        except Exception as e:
            self.fail(f"Pipeline crashed on empty input: {e}")


# ══════════════════════════════════════════════════════════════════
#  EDGE CASE TESTS
# ══════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):

    def test_EC01_empty_input_returns_none_fields(self):
        """EC-01: Empty input produces ParsedHeader with None fields."""
        result = HeaderParser().parse(EMPTY_HEADER)
        self.assertIsNone(result.sender)
        self.assertIsNone(result.subject)

    def test_EC02_missing_auth_headers_returns_none(self):
        """EC-02: Header with no auth fields returns None for SPF/DKIM/DMARC."""
        result = HeaderParser().parse(MINIMAL_HEADER)
        self.assertIsNone(result.spf)
        self.assertIsNone(result.dkim)
        self.assertIsNone(result.dmarc)

    def test_EC03_no_received_headers_returns_empty_hops(self):
        """EC-03: Header with no Received fields produces empty hop list."""
        parsed = HeaderParser().parse(MINIMAL_HEADER)
        hops = HopAnalyser().analyse(parsed.received_hops)
        self.assertEqual(hops, [])

    def test_EC04_malformed_timestamp_does_not_crash(self):
        """EC-04: Malformed timestamp in Received header is handled gracefully."""
        raw_hops = [{
            "raw": "raw",
            "from": "server1.com",
            "by": "server2.com",
            "timestamp": "THIS IS NOT A VALID DATE",
        }]
        try:
            hops = HopAnalyser().analyse(raw_hops)
            self.assertIsNone(hops[0].timestamp)
        except Exception as e:
            self.fail(f"Crashed on malformed timestamp: {e}")

    def test_EC05_plain_text_input_does_not_crash(self):
        """EC-05: Plain text input (not a header) runs without crashing."""
        plain_text = "Hello, this is not an email header at all."
        try:
            result = HeaderParser().parse(plain_text)
            self.assertIsNone(result.spf)
        except Exception as e:
            self.fail(f"Crashed on plain text input: {e}")

    def test_EC06_all_eight_samples_parse_without_crash(self):
        """EC-06: All eight sample headers parse through full pipeline without error."""
        samples = [
            PHISHING_HEADER, LEGITIMATE_HEADER, SPOOFED_HEADER,
            BEC_HEADER, FAKE_PASSWORD_RESET_HEADER, LEGITIMATE_OUTLOOK_HEADER,
            NEWSLETTER_HEADER, MALWARE_HEADER,
        ]
        for i, sample in enumerate(samples):
            with self.subTest(sample_index=i):
                try:
                    parsed = HeaderParser().parse(sample)
                    hops = HopAnalyser().analyse(parsed.received_hops)
                    RiskEngine().evaluate(
                        sender=parsed.sender,
                        reply_to=parsed.reply_to,
                        return_path=parsed.return_path,
                        spf=parsed.spf,
                        dkim=parsed.dkim,
                        dmarc=parsed.dmarc,
                        hops=hops,
                    )
                except Exception as e:
                    self.fail(f"Sample {i} crashed: {e}")


# ══════════════════════════════════════════════════════════════════
#  RUNNER
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)