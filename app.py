from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator

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

# Step 1 — parse
parser = HeaderParser()
parsed = parser.parse(sample)

# Step 2 — evaluate auth
evaluator = AuthEvaluator()
auth_results = evaluator.evaluate(parsed.spf, parsed.dkim, parsed.dmarc)

print("=== AUTHENTICATION EVALUATION ===")
for auth in auth_results:
    print(f"\n{auth.protocol}")
    print(f"  Result:      {auth.result}")
    print(f"  Status:      {auth.status}")
    print(f"  Colour:      {auth.colour}")
    print(f"  Explanation: {auth.explanation}")