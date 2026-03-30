from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser

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

# Parse
parser = HeaderParser()
parsed = parser.parse(sample)

# Evaluate auth
evaluator = AuthEvaluator()
auth_results = evaluator.evaluate(parsed.spf, parsed.dkim, parsed.dmarc)

# Analyse hops
analyser = HopAnalyser()
hops = analyser.analyse(parsed.received_hops)

print("=== HOP ANALYSIS ===")
for hop in hops:
    delay_info = f"  Delay: {hop.delay_label}" if hop.delay_label else "  Delay: (first hop)"
    suspicious = "  ⚠ SUSPICIOUS DELAY" if hop.suspicious else ""
    print(f"\nHop {hop.index}")
    print(f"  From: {hop.from_server}")
    print(f"  By:   {hop.by_server}")
    print(f"  Time: {hop.timestamp}")
    print(delay_info + suspicious)