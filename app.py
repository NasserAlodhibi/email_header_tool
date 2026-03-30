import streamlit as st # type: ignore
import os
from parser.header_parser import HeaderParser
from parser.auth_evaluator import AuthEvaluator
from parser.hop_analyser import HopAnalyser
from engine.risk_engine import RiskEngine
from visualisation.hop_chart import build_hop_chart

# ── Page config ───────────────────────────────────────────────────
st.set_page_config(
    page_title="Email Header Analyser",
    page_icon="🔍",
    layout="wide",
)

# ── Styling ───────────────────────────────────────────────────────
st.markdown("""
<style>
    .risk-high   { background:#FDEDEC; border-left:5px solid #E74C3C; padding:16px; border-radius:6px; }
    .risk-medium { background:#FEF9E7; border-left:5px solid #F39C12; padding:16px; border-radius:6px; }
    .risk-low    { background:#EAFAF1; border-left:5px solid #2ECC71; padding:16px; border-radius:6px; }
    .badge-high   { background:#E74C3C; color:white; padding:3px 10px; border-radius:12px; font-size:13px; font-weight:bold; }
    .badge-medium { background:#F39C12; color:white; padding:3px 10px; border-radius:12px; font-size:13px; font-weight:bold; }
    .badge-low    { background:#2ECC71; color:white; padding:3px 10px; border-radius:12px; font-size:13px; font-weight:bold; }
    .badge-pass   { background:#2ECC71; color:white; padding:3px 10px; border-radius:12px; font-size:13px; }
    .badge-fail   { background:#E74C3C; color:white; padding:3px 10px; border-radius:12px; font-size:13px; }
    .badge-warn   { background:#F39C12; color:white; padding:3px 10px; border-radius:12px; font-size:13px; }
    .badge-none   { background:#95A5A6; color:white; padding:3px 10px; border-radius:12px; font-size:13px; }
    .field-label { font-weight:bold; color:#555; font-size:13px; }
    .field-value { font-size:14px; color:#222; }
    .flag-high   { border-left:4px solid #E74C3C; padding:10px 14px; margin:6px 0; background:#FFF5F5; border-radius:4px; }
    .flag-medium { border-left:4px solid #F39C12; padding:10px 14px; margin:6px 0; background:#FFFBF0; border-radius:4px; }
    .flag-low    { border-left:4px solid #95A5A6; padding:10px 14px; margin:6px 0; background:#F8F9FA; border-radius:4px; }
</style>
""", unsafe_allow_html=True)

# ── Sample headers ────────────────────────────────────────────────
def _load_sample(filename: str) -> str:
    """Load a sample header from the samples/ folder."""
    path = os.path.join(os.path.dirname(__file__), "samples", filename)
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""

SAMPLES = {
    "🎣 Phishing Email": _load_sample("phishing.eml"),
    "✅ Legitimate Email": _load_sample("legitimate.eml"),
    "🎭 Spoofed (CEO Fraud)": _load_sample("spoofed.eml"),
}

# ── Header ────────────────────────────────────────────────────────
st.title("🔍 Email Header Analyser")
st.markdown("Paste a raw email header below to analyse its origin, authentication, and risk level.")
st.divider()

# ── Input section ─────────────────────────────────────────────────
col_input, col_sample = st.columns([3, 1])

with col_sample:
    st.markdown("**Load a sample header:**")
    for name in SAMPLES:
        if st.button(name, width="stretch"):
            st.session_state["header_input"] = SAMPLES[name]

with col_input:
    header_text = st.text_area(
        "Raw Email Header",
        value=st.session_state.get("header_input", ""),
        height=220,
        placeholder="Paste your raw email header here...",
        label_visibility="collapsed",
    )

st.divider()

# ── Analyse button ────────────────────────────────────────────────
if st.button("🔎 Analyse Header", type="primary", width="stretch"):
    if not header_text.strip():
        st.warning("Please paste an email header or load a sample first.")
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

        # ── Tabs ──────────────────────────────────────────────────
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Overview",
            "🗺️ Hop Path",
            "📋 Raw Fields",
            "📚 What Does This Mean?",
        ])

        # ════════════════════════════════════════════════════════
        #  TAB 1 — OVERVIEW
        # ════════════════════════════════════════════════════════
        with tab1:

            # Risk banner
            level = report.level
            css_class = f"risk-{level.lower()}"
            badge_class = f"badge-{level.lower()}"
            icon = "🔴" if level == "High" else "🟡" if level == "Medium" else "🟢"

            st.markdown(f"""
            <div class="{css_class}">
                <span style="font-size:22px; font-weight:bold;">{icon} Risk Level:
                    <span class="{badge_class}">{level}</span>
                </span>
                <p style="margin:8px 0 0 0; color:#444;">{report.summary}</p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Auth results row
            st.markdown("#### Authentication Results")
            a1, a2, a3 = st.columns(3)

            for col, auth in zip([a1, a2, a3], auth_res):
                badge = f"badge-{auth.status}"
                with col:
                    st.markdown(f"""
                    <div style="border:1px solid #ddd; border-radius:8px; padding:16px; text-align:center;">
                        <div style="font-size:16px; font-weight:bold; margin-bottom:6px;">{auth.protocol}</div>
                        <div><span class="{badge}">{auth.result.upper()}</span></div>
                        <div style="font-size:12px; color:#666; margin-top:10px;">{auth.explanation}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Flags
            if report.flags:
                st.markdown("#### Suspicious Indicators")
                for flag in report.flags:
                    css = f"flag-{flag.severity}"
                    icon_f = "🔴" if flag.severity == "high" else "🟡" if flag.severity == "medium" else "⚪"
                    st.markdown(f"""
                    <div class="{css}">
                        <strong>{icon_f} {flag.title}</strong>
                        <p style="margin:4px 0 0 0; color:#555; font-size:13px;">{flag.detail}</p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No suspicious indicators detected.")

            st.markdown("<br>", unsafe_allow_html=True)

            # Basic fields summary
            st.markdown("#### Email Summary")
            fields = [
                ("From", parsed.sender),
                ("Reply-To", parsed.reply_to),
                ("Subject", parsed.subject),
                ("Date", parsed.date),
                ("Message-ID", parsed.message_id),
                ("Return-Path", parsed.return_path),
                ("Originating IP", parsed.originating_ip),
            ]
            for label, value in fields:
                if value:
                    c1, c2 = st.columns([1, 3])
                    with c1:
                        st.markdown(f"<span class='field-label'>{label}</span>", unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"<span class='field-value'>{value}</span>", unsafe_allow_html=True)

        # ════════════════════════════════════════════════════════
        #  TAB 2 — HOP PATH
        # ════════════════════════════════════════════════════════
        with tab2:
            st.markdown("#### Email Routing Path")
            st.markdown("This chart shows every server the email passed through, in chronological order.")

            if chart:
                st.plotly_chart(chart, width="stretch")
            else:
                st.info("No routing information found in this header.")

            if hops:
                st.markdown("#### Hop Details")
                for hop in hops:
                    delay_str = f"⏱ {hop.delay_label}" if hop.delay_label else "⏱ First hop"
                    warn = " ⚠️ Suspicious delay" if hop.suspicious else ""
                    with st.expander(f"Hop {hop.index} — {hop.by_server or 'Unknown server'}{warn}"):
                        st.markdown(f"**From:** `{hop.from_server or 'Unknown'}`")
                        st.markdown(f"**By:** `{hop.by_server or 'Unknown'}`")
                        st.markdown(f"**Timestamp:** `{hop.timestamp_raw or 'Not found'}`")
                        st.markdown(f"**Delay:** {delay_str}")
                        with st.expander("Raw header"):
                            st.code(hop.raw, language=None)

        # ════════════════════════════════════════════════════════
        #  TAB 3 — RAW FIELDS
        # ════════════════════════════════════════════════════════
        with tab3:
            st.markdown("#### All Extracted Header Fields")
            st.markdown("Every field found in the raw header, displayed as key-value pairs.")
            if parsed.raw_headers:
                for key, value in parsed.raw_headers.items():
                    with st.expander(f"`{key}`"):
                        st.code(value, language=None)
            else:
                st.info("No fields could be extracted.")

        # ════════════════════════════════════════════════════════
        #  TAB 4 — EDUCATION
        # ════════════════════════════════════════════════════════
        with tab4:
            st.markdown("#### Understanding Email Headers")

            with st.expander("📌 What is an email header?"):
                st.markdown("""
An email header is a block of metadata prepended to every email message.
It records the complete journey of the email from sender to recipient,
including every server it passed through, when it arrived, and the results
of security checks performed along the way.

Unlike the email body (which you normally read), headers are hidden by default
in most email clients. To view them you typically need to use
**Show Original**, **View Source**, or **Message Details** in your email client.
                """)

            with st.expander("🔐 What is SPF?"):
                st.markdown("""
**Sender Policy Framework (SPF)** allows a domain owner to publish a list of
IP addresses that are authorised to send email on behalf of their domain.

When a mail server receives an email, it checks the sending IP against
the domain's SPF DNS record.

| Result | Meaning |
|--------|---------|
| pass | The server is authorised ✅ |
| fail | The server is NOT authorised ❌ |
| softfail | Not authorised but not enforced ⚠️ |
| none | No SPF record exists |
                """)

            with st.expander("✍️ What is DKIM?"):
                st.markdown("""
**DomainKeys Identified Mail (DKIM)** adds a cryptographic digital signature
to outgoing emails. The recipient's mail server uses the sender's public key
(published in DNS) to verify the signature.

A **DKIM pass** means the message was not altered in transit and genuinely
came from the declared domain.

A **DKIM fail** means the signature is invalid — the message may have been
tampered with, or forged entirely.
                """)

            with st.expander("🛡️ What is DMARC?"):
                st.markdown("""
**Domain-based Message Authentication, Reporting and Conformance (DMARC)**
builds on SPF and DKIM by letting domain owners define a *policy* for what
happens when emails fail authentication.

DMARC requires **alignment** — the domain in the From header must match the
domain that passed SPF or DKIM.

| Policy | Action on failure |
|--------|-------------------|
| none | No action — monitoring only |
| quarantine | Send to spam folder |
| reject | Block the email entirely |

A DMARC **pass** is the strongest indicator that an email is legitimate.
                """)

            with st.expander("🔴 What makes an email suspicious?"):
                st.markdown("""
The following are the most common indicators of phishing or spoofing:

- **SPF fail** — the sending server is not authorised for the From domain
- **DMARC fail** — the email failed the domain's authentication policy
- **Reply-To mismatch** — replies would go to a completely different domain than the sender
- **Return-Path mismatch** — bounce messages would go to a different domain
- **Long hop delays** — unusual delays between servers may indicate message holding
- **Missing authentication** — no SPF, DKIM, or DMARC records at all

No single flag is definitive proof of phishing. Look at the combination of indicators.
                """)