# Email Header Analyser

A locally-run Python tool for analysing and visualising raw email headers. Built as part of my CI6600 Individual Project (BSc Cyber Security, Kingston University, 2025–26).

The tool parses raw email headers, evaluates SPF/DKIM/DMARC authentication results, traces the routing path through a hop-by-hop timeline, and produces a risk score based on common phishing and spoofing indicators — all through an interactive Streamlit dashboard.

---

## What it does

- Parses raw email headers using Python's built-in `email` module (RFC 5322 compliant), with regex fallbacks for non-standard fields
- Evaluates SPF, DKIM, and DMARC results with colour-coded status badges and plain-English explanations
- Traces the routing path in chronological order and calculates inter-hop delays
- Flags suspicious delays (>30 minutes), Reply-To mismatches, Return-Path mismatches, and authentication failures
- Calculates an overall risk score (Low / Medium / High) based on weighted flag severity
- Visualises the hop path as an interactive Plotly timeline
- Optionally looks up the geographic location of each server IP (requires internet connection)
- Exports the full analysis as a JSON report
- Includes eight sample email headers covering phishing, spoofing, BEC, malware delivery, and legitimate email scenarios
- Has an educational tab explaining SPF, DKIM, DMARC, and common phishing indicators in plain language

---

## Project structure

```
email_header_tool/
├── app.py
├── engine
│   ├── geo_engine.py
│   ├── __init__.py
│   └── risk_engine.py
├── parser
│   ├── auth_evaluator.py
│   ├── header_parser.py
│   ├── hop_analyser.py
│   ├── __init__.py
├── pyproject.toml
├── README.md
├── samples
│   ├── bec_invoice.eml
│   ├── fake_password_reset.eml
│   ├── legitimate.eml
│   ├── legitimate_outlook.eml
│   ├── malware_delivery.eml
│   ├── newsletter_legitimate.eml
│   ├── phishing.eml
│   └── spoofed.eml
├── test_tool.py
├── uv.lock
└── visualisation
    ├── hop_chart.py
    ├── __init__.py
```

---

## Requirements

- Python 3.10 or above
- [uv](https://github.com/astral-sh/uv) package manager

---

## Setup and running

Clone the repository and navigate into the project folder, then run:

```bash
uv sync
uv run streamlit run app.py
```

Streamlit will open the application in your default browser at `http://localhost:8501`.

If you do not have `uv` installed:

```bash
pip install uv
```

---

## How to use

1. Paste a raw email header into the text area, or use the sidebar dropdown to load one of the eight built-in sample headers
2. Click **Analyse Header**
3. Results are split across four tabs:
   - **Overview** — risk level banner, authentication cards, suspicious flags, and key email fields
   - **Hop Path** — interactive routing timeline and expandable hop details; enable IP Geolocation in the sidebar to add a map
   - **Raw Fields** — all extracted header key-value pairs
   - **What Does This Mean?** — educational explanations of email headers, SPF, DKIM, DMARC, and phishing indicators
4. Use the **Download Analysis Report (JSON)** button at the bottom to export the full results

To get the raw header from your email client:
- **Gmail**: open the email → three-dot menu → "Show original"
- **Outlook**: open the email → File → Properties → "Internet headers"
- **Apple Mail**: View → Message → "All Headers"

---

## Running the tests

```bash
uv run python test_tool.py
```

The test suite has 52 automated tests across five classes: `TestHeaderParser`, `TestAuthEvaluator`, `TestHopAnalyser`, `TestFullPipeline`, and `TestEdgeCases`.

---

## Sample headers

Eight synthetic sample headers are included in the `samples/` directory. All IP addresses, email addresses, and domain names are either fictitious or from reserved documentation ranges and do not correspond to real persons or servers.

| File | Scenario | Expected Risk |
|------|----------|---------------|
| `phishing.eml` | Fake PayPal security notice | High |
| `legitimate.eml` | Legitimate Gmail message | Low |
| `spoofed.eml` | CEO fraud with spoofed From domain | High |
| `bec_invoice.eml` | Business email compromise fake invoice | High |
| `fake_password_reset.eml` | Lookalike domain phishing | High |
| `legitimate_outlook.eml` | Legitimate Microsoft 365 corporate email | Low |
| `newsletter_legitimate.eml` | Third-party bulk mail (MailChimp) | Medium |
| `malware_delivery.eml` | Fake payroll notification with suspicious routing | High |

---

## Known limitations

- IP geolocation uses the free ip-api.com service, which has rate limits and requires an internet connection
- The tool analyses headers only — it does not fetch live email or connect to mail servers
- The risk scoring thresholds were calibrated on the eight sample headers and may not generalise to all real-world email formats
- DMARC policy enforcement level (none/quarantine/reject) is not currently parsed from the header

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| streamlit | >=1.55.0 | Web UI framework |
| plotly | >=6.6.0 | Interactive hop path chart |
| mail-parser | >=4.1.4 | Supplementary header parsing |
| geoip2 | >=5.2.0 | IP geolocation lookups |

Full dependency pins are in `pyproject.toml` and `uv.lock`.
