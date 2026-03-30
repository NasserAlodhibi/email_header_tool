from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser
from engine.risk_engine import RiskEngine

sample = """From: attacker@evil.com
Reply-To: real@gmail.com
Subject: You won a prize!
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <abc123@evil.com>
Return-Path: <bounce@evil.com>
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of attacker@evil.com does not designate)
       dkim=pass header.i=@evil.com
       dmarc=fail
Received: from mail.evil.com (mail.evil.com [192.168.1.1])
        by mx.google.com with ESMTP; Mon, 01 Jan 2024 10:00:01 +0000
Received: from [10.0.0.1] (unknown)
        by mail.evil.com with SMTP; Mon, 01 Jan 2024 09:59:55 +0000
"""

# Full pipeline
parser = HeaderParser()
parsed = parser.parse(sample)

evaluator = AuthEvaluator()
auth_results = evaluator.evaluate(parsed.spf, parsed.dkim, parsed.dmarc)

analyser = HopAnalyser()
hops = analyser.analyse(parsed.received_hops)

engine = RiskEngine()
report = engine.evaluate(
    sender=parsed.sender,
    reply_to=parsed.reply_to,
    return_path=parsed.return_path,
    spf=parsed.spf,
    dkim=parsed.dkim,
    dmarc=parsed.dmarc,
    hops=hops,
)

print("=== RISK REPORT ===")
print(f"Level:   {report.level}")
print(f"Score:   {report.score}/100")
print(f"Summary: {report.summary}")
print(f"\nFlags ({len(report.flags)}):")
for flag in report.flags:
    print(f"  [{flag.severity.upper()}] {flag.title}")
    print(f"         {flag.detail}")