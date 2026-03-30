from parser.header_parser import HeaderParser

# A small sample header to test with
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
result = parser.parse(sample)

print("=== BASIC FIELDS ===")
print(f"From:        {result.sender}")
print(f"Reply-To:    {result.reply_to}")
print(f"Subject:     {result.subject}")
print(f"Date:        {result.date}")
print(f"Message-ID:  {result.message_id}")
print(f"Return-Path: {result.return_path}")

print("\n=== AUTHENTICATION ===")
print(f"SPF:   {result.spf}")
print(f"DKIM:  {result.dkim}")
print(f"DMARC: {result.dmarc}")

print("\n=== HOP CHAIN ===")
for i, hop in enumerate(result.received_hops, 1):
    print(f"Hop {i}: {hop['from']} → {hop['by']}  |  {hop['timestamp']}")