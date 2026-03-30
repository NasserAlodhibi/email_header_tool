from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser
from engine.risk_engine import RiskEngine
from visualisation.hop_chart import build_hop_chart

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

parser = HeaderParser()
parsed = parser.parse(sample)

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

chart = build_hop_chart(hops)

print("=== FULL PIPELINE CHECK ===")
print(f"Hops parsed:    {len(hops)}")
print(f"Risk level:     {report.level}")
print(f"Flags:          {len(report.flags)}")
print(f"Chart built:    {'Yes' if chart else 'No'}")
print(f"Chart type:     {type(chart)}")
print("\nAll systems go." if chart else "\nChart failed.")