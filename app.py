import json
import datetime
import pandas as pd
import streamlit as st
import os
from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser
from engine.risk_engine import RiskEngine
from engine.geo_engine import GeoEngine
from visualisation.hop_chart import build_hop_chart


st.set_page_config(
    page_title="Email Header Analyser",
    layout="wide",
)

st.markdown("""
<style>
    .risk-high   { background:#fff5f5; border-left:4px solid #c0392b; padding:16px 20px; border-radius:4px; }
    .risk-medium { background:#fffbf0; border-left:4px solid #e67e22; padding:16px 20px; border-radius:4px; }
    .risk-low    { background:#f0faf4; border-left:4px solid #27ae60; padding:16px 20px; border-radius:4px; }
    .badge-high   { background:#c0392b; color:white; padding:2px 10px; border-radius:3px; font-size:13px; font-weight:600; letter-spacing:0.03em; }
    .badge-medium { background:#e67e22; color:white; padding:2px 10px; border-radius:3px; font-size:13px; font-weight:600; letter-spacing:0.03em; }
    .badge-low    { background:#27ae60; color:white; padding:2px 10px; border-radius:3px; font-size:13px; font-weight:600; letter-spacing:0.03em; }
    .badge-pass   { background:#27ae60; color:white; padding:2px 8px; border-radius:3px; font-size:12px; }
    .badge-fail   { background:#c0392b; color:white; padding:2px 8px; border-radius:3px; font-size:12px; }
    .badge-warn   { background:#e67e22; color:white; padding:2px 8px; border-radius:3px; font-size:12px; }
    .badge-none   { background:#7f8c8d; color:white; padding:2px 8px; border-radius:3px; font-size:12px; }
    .field-label  { font-weight:600; color:#555; font-size:13px; }
    .field-value  { font-size:13px; color:#222; }
    .flag-high    { border-left:3px solid #c0392b; padding:10px 14px; margin:4px 0; background:#fff5f5; border-radius:3px; }
    .flag-medium  { border-left:3px solid #e67e22; padding:10px 14px; margin:4px 0; background:#fffbf0; border-radius:3px; }
    .flag-low     { border-left:3px solid #95a5a6; padding:10px 14px; margin:4px 0; background:#f8f9fa; border-radius:3px; }
    .auth-card    { border:1px solid #e0e0e0; border-radius:6px; padding:16px; text-align:center; background:#fafafa; }
    .geo-pill     { display:inline-block; background:#eef2f7; color:#333; font-size:12px;
                    padding:2px 8px; border-radius:10px; margin-top:4px; }
    .section-label { font-size:11px; font-weight:600; text-transform:uppercase;
                     letter-spacing:0.06em; color:#999; margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)


def _load_sample(filename: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "samples", filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


SAMPLES = {
    "Phishing Email":          _load_sample("phishing.eml"),
    "Legitimate Gmail":        _load_sample("legitimate.eml"),
    "Spoofed CEO Fraud":       _load_sample("spoofed.eml"),
    "BEC Fake Invoice":        _load_sample("bec_invoice.eml"),
    "Fake Password Reset":     _load_sample("fake_password_reset.eml"),
    "Legitimate Outlook":      _load_sample("legitimate_outlook.eml"),
    "Newsletter (Legitimate)": _load_sample("newsletter_legitimate.eml"),
    "Malware Delivery":        _load_sample("malware_delivery.eml"),
}


with st.sidebar:
    st.markdown("## Sample Headers")
    st.caption("Load a pre-built header to explore the tool.")
    selected_sample = st.selectbox(
        "Select a sample",
        options=[""] + list(SAMPLES.keys()),
        label_visibility="collapsed",
    )
    if st.button("Load Sample", disabled=not selected_sample, width='stretch'):
        st.session_state["header_input"] = SAMPLES[selected_sample]
        st.rerun()

    st.divider()
    st.markdown("## Options")
    geo_enabled = st.toggle(
        "IP Geolocation",
        key="geo_enabled",
        help="Look up the geographic location of each server in the routing path. Requires an internet connection.",
    )

    st.divider()
    st.markdown("## About")
    st.caption(
        "Parses raw email headers to show sender information, authentication results "
        "(SPF, DKIM, DMARC), routing hops, and a risk score based on common phishing "
        "and spoofing indicators."
    )


def _build_export(parsed, auth_res, hops, report, geo_results: dict) -> str:
    hop_list = []
    for hop in hops:
        geo = geo_results.get(hop.index)
        hop_list.append({
            "index": hop.index,
            "from":  hop.from_server,
            "by":    hop.by_server,
            "timestamp": hop.timestamp_raw,
            "delay_seconds": hop.delay_seconds,
            "suspicious": hop.suspicious,
            "location": {
                "ip":      geo.ip      if geo else None,
                "city":    geo.city    if geo else None,
                "country": geo.country if geo else None,
                "org":     geo.org     if geo else None,
            } if geo else None,
        })

    export = {
        "analysed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "risk": {
            "level":   report.level,
            "score":   report.score,
            "summary": report.summary,
        },
        "email": {
            "from":           parsed.sender,
            "reply_to":       parsed.reply_to,
            "subject":        parsed.subject,
            "date":           parsed.date,
            "message_id":     parsed.message_id,
            "return_path":    parsed.return_path,
            "originating_ip": parsed.originating_ip,
        },
        "authentication": {
            "spf":   parsed.spf,
            "dkim":  parsed.dkim,
            "dmarc": parsed.dmarc,
        },
        "flags": [
            {
                "code":     f.code,
                "severity": f.severity,
                "title":    f.title,
                "detail":   f.detail,
            }
            for f in report.flags
        ],
        "hops": hop_list,
    }
    return json.dumps(export, indent=2)


st.title("Email Header Analyser")
st.caption("Paste a raw email header to analyse its origin, authentication, and risk level.")
st.divider()

header_text = st.text_area(
    "Raw Email Header",
    value=st.session_state.get("header_input", ""),
    height=220,
    placeholder="Paste your raw email header here...",
    label_visibility="collapsed",
)

if st.button("Analyse Header", type="primary", width='stretch'):
    if not header_text.strip():
        st.warning("Paste an email header or load a sample first.")
    else:
        with st.spinner("Analysing..."):
            parsed   = HeaderParser().parse(header_text)
            auth_res = AuthEvaluator().evaluate(parsed.spf, parsed.dkim, parsed.dmarc)
            hops     = HopAnalyser().analyse(parsed.received_hops)
            report   = RiskEngine().evaluate(
                sender=parsed.sender,
                reply_to=parsed.reply_to,
                return_path=parsed.return_path,
                spf=parsed.spf,
                dkim=parsed.dkim,
                dmarc=parsed.dmarc,
                hops=hops,
            )
            chart = build_hop_chart(hops)

            geo_results = {}
            if geo_enabled and hops:
                geo_engine = GeoEngine()
                for hop in hops:
                    ip = geo_engine.extract_ip(hop.raw)
                    if ip:
                        geo_results[hop.index] = geo_engine.lookup(ip)

        st.session_state["analysis"] = {
            "parsed":      parsed,
            "auth_res":    auth_res,
            "hops":        hops,
            "report":      report,
            "chart":       chart,
            "geo_results": geo_results,
        }


if "analysis" in st.session_state:
    a        = st.session_state["analysis"]
    parsed   = a["parsed"]
    auth_res = a["auth_res"]
    hops     = a["hops"]
    report   = a["report"]
    chart    = a["chart"]
    geo_results = a["geo_results"]

    tab1, tab2, tab3, tab4 = st.tabs([
        "Overview", "Hop Path", "Raw Fields", "What Does This Mean?",
    ])

    with tab1:
        level       = report.level
        css_class   = f"risk-{level.lower()}"
        badge_class = f"badge-{level.lower()}"

        st.markdown(f"""
        <div class="{css_class}">
            <span style="font-size:18px; font-weight:600;">Risk Level:
                <span class="{badge_class}">{level.upper()}</span>
            </span>
            <p style="margin:8px 0 0; color:#555; font-size:14px;">{report.summary}</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        m1, m2, m3 = st.columns(3)
        m1.metric("Risk Score", f"{report.score} / 100")
        m2.metric("Flags Detected", len(report.flags))
        m3.metric("Routing Hops", len(hops))

        st.divider()
        st.markdown('<div class="section-label">Authentication</div>', unsafe_allow_html=True)
        a1, a2, a3 = st.columns(3)

        for col, auth in zip([a1, a2, a3], auth_res):
            badge = f"badge-{auth.status}"
            with col:
                st.markdown(f"""
                <div class="auth-card">
                    <div style="font-size:15px; font-weight:600; margin-bottom:6px;">{auth.protocol}</div>
                    <div><span class="{badge}">{auth.result.upper()}</span></div>
                    <div style="font-size:12px; color:#666; margin-top:8px;">{auth.explanation}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        if report.flags:
            st.markdown('<div class="section-label">Suspicious Indicators</div>', unsafe_allow_html=True)
            for flag in report.flags:
                css = f"flag-{flag.severity}"
                st.markdown(f"""
                <div class="{css}">
                    <strong>[{flag.severity.upper()}] {flag.title}</strong>
                    <p style="margin:4px 0 0; color:#555; font-size:13px;">{flag.detail}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No suspicious indicators detected.")

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-label">Email Summary</div>', unsafe_allow_html=True)

        fields = [
            ("From",           parsed.sender),
            ("Reply-To",       parsed.reply_to),
            ("Subject",        parsed.subject),
            ("Date",           parsed.date),
            ("Message-ID",     parsed.message_id),
            ("Return-Path",    parsed.return_path),
            ("Originating IP", parsed.originating_ip),
        ]
        for label, value in fields:
            if value:
                c1, c2 = st.columns([1, 3])
                with c1:
                    st.markdown(f"<span class='field-label'>{label}</span>", unsafe_allow_html=True)
                with c2:
                    st.markdown(f"<span class='field-value'>{value}</span>", unsafe_allow_html=True)

    with tab2:
        st.markdown("#### Email Routing Path")
        st.caption("Every server the email passed through, in chronological order.")

        if chart:
            st.plotly_chart(chart, width='stretch')
        else:
            st.info("No routing information found in this header.")

        if geo_results:
            map_rows = [
                {"lat": g.lat, "lon": g.lon, "label": f"Hop {idx} — {g.location}"}
                for idx, g in geo_results.items()
                if g.lat and g.lon
            ]
            if map_rows:
                st.markdown("#### Server Locations")
                st.caption("Geographic location of each server in the routing path.")
                st.map(pd.DataFrame(map_rows), latitude="lat", longitude="lon")

        if hops:
            st.markdown("#### Hop Details")
            for hop in hops:
                delay_str = hop.delay_label if hop.delay_label else "First hop"
                warn      = "  [Suspicious delay]" if hop.suspicious else ""
                geo       = geo_results.get(hop.index)

                with st.expander(f"Hop {hop.index} — {hop.by_server or 'Unknown server'}{warn}"):
                    st.markdown(f"**From:** `{hop.from_server or 'Unknown'}`")
                    st.markdown(f"**By:** `{hop.by_server or 'Unknown'}`")
                    st.markdown(f"**Timestamp:** `{hop.timestamp_raw or 'Not found'}`")
                    st.markdown(f"**Delay:** {delay_str}")

                    if geo and not geo.error:
                        parts = [p for p in [geo.city, geo.country] if p]
                        location_str = ", ".join(parts) if parts else "Unknown"
                        org_str = geo.org or ""
                        st.markdown(
                            f'<span class="geo-pill">IP: {geo.ip}</span> '
                            f'<span class="geo-pill">{location_str}</span>'
                            + (f' <span class="geo-pill">{org_str}</span>' if org_str else ""),
                            unsafe_allow_html=True,
                        )

                    with st.expander("Raw header"):
                        st.code(hop.raw, language=None)

    with tab3:
        st.markdown("#### All Extracted Header Fields")
        if parsed.raw_headers:
            for key, value in parsed.raw_headers.items():
                with st.expander(f"`{key}`"):
                    st.code(value, language=None)
        else:
            st.info("No fields could be extracted.")

    with tab4:
        st.markdown("#### Understanding Email Headers")

        with st.expander("What is an email header?"):
            st.markdown("""
An email header is metadata prepended to every message. It records the complete journey
from sender to recipient — every server it passed through, when it arrived, and the results
of security checks performed along the way.

Headers are hidden by default in most clients. To view them use
**Show Original**, **View Source**, or **Message Details**.
            """)

        with st.expander("What is SPF?"):
            st.markdown("""
**Sender Policy Framework (SPF)** lets a domain owner publish the IP addresses
authorised to send email on its behalf. The receiving server checks the sending IP against this list.

| Result | Meaning |
|--------|---------|
| pass | The server is authorised |
| fail | The server is NOT authorised |
| softfail | Not authorised but not enforced |
| none | No SPF record exists |
            """)

        with st.expander("What is DKIM?"):
            st.markdown("""
**DomainKeys Identified Mail (DKIM)** adds a cryptographic signature to outgoing email.
The recipient's server uses the sender's public key (published in DNS) to verify it.

A **pass** means the message was not altered in transit.
A **fail** means the signature is invalid — the message may have been tampered with or forged.
            """)

        with st.expander("What is DMARC?"):
            st.markdown("""
**DMARC** builds on SPF and DKIM. It lets domain owners define a policy for what happens
when emails fail authentication, and requires the From address to align with the domain
that passed SPF or DKIM.

| Policy | Action on failure |
|--------|-------------------|
| none | Monitor only |
| quarantine | Move to spam |
| reject | Block entirely |
            """)

        with st.expander("What makes an email suspicious?"):
            st.markdown("""
Common indicators of phishing or spoofing:

- **SPF fail** — the sending server is not authorised for the From domain
- **DMARC fail** — the email failed the domain's authentication policy
- **Reply-To mismatch** — replies would go to a different domain than the sender
- **Return-Path mismatch** — bounces would go to a different domain
- **Long hop delays** — unusual server delays may indicate message holding
- **Missing authentication** — no SPF, DKIM, or DMARC records at all

No single flag is definitive. Look at the combination of indicators.
            """)

    st.divider()
    export_json = _build_export(parsed, auth_res, hops, report, geo_results)
    st.download_button(
        label="Download Analysis Report (JSON)",
        data=export_json,
        file_name="email_analysis.json",
        mime="application/json",
        width='stretch',
    )
