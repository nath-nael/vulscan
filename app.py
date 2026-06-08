import streamlit as st
import requests
import urllib3
import pandas as pd
import json
from datetime import datetime
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner.crawler import crawl
from scanner.csrf_scanner import run_csrf_scan
from scanner.headers_scanner import run_headers_scan
from scanner.info_leakage import run_info_leakage_scan
from scanner.sql_scanner import run_sql_scan
from scanner.ssl_scanner import run_ssl_scan
from scanner.xss_scanner import run_xss_scan

# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="WebVulnScanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    .main-title {
        font-size: 2.5rem;
        font-weight: 700;
        color: #e63946;
        text-align: center;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1rem;
        color: #adb5bd;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-critical {
        background-color: #7d0000;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .severity-high {
        background-color: #c0392b;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .severity-medium {
        background-color: #e67e22;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .severity-low {
        background-color: #f1c40f;
        color: black;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .severity-info {
        background-color: #2980b9;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        border: 1px solid #333;
    }
    .stProgress > div > div > div > div {
        background-color: #e63946;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #333;
        border-radius: 8px;
        margin-bottom: 6px;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLORS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "⚪"
}


def severity_badge(severity: str) -> str:
    css_class = f"severity-{severity.lower()}"
    return f'<span class="{css_class}">{severity}</span>'


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Info"), 99))


def build_summary(findings: list) -> dict:
    counts = Counter(f.get("severity", "Info") for f in findings)
    return {
        "Critical": counts.get("Critical", 0),
        "High": counts.get("High", 0),
        "Medium": counts.get("Medium", 0),
        "Low": counts.get("Low", 0),
        "Info": counts.get("Info", 0),
        "Total": len(findings)
    }


def findings_to_df(findings: list) -> pd.DataFrame:
    rows = []
    for f in findings:
        rows.append({
            "Severity": f.get("severity", "Info"),
            "Type": f.get("type", ""),
            "URL": f.get("url", ""),
            "Detail": f.get("detail", ""),
            "Evidence": f.get("evidence", ""),
            "Recommendation": f.get("recommendation", "")
        })
    return pd.DataFrame(rows)


def run_scan(target_url: str, options: dict, max_urls: int) -> list:
    """Orchestrate the full scan and stream results."""
    session = requests.Session()
    session.verify = False
    all_findings = []

    progress = st.progress(0, text="🕷️ Crawling target...")
    status = st.empty()

    # Step 1: Crawl
    status.info("🕷️ Crawling website...")
    urls = crawl(target_url, max_urls=max_urls)
    if not urls:
        urls = [target_url]
    progress.progress(10, text=f"✅ Found {len(urls)} URLs")

    steps = [k for k, v in options.items() if v]
    step_size = int(80 / max(len(steps), 1))
    current = 10

    # Step 2: Run selected scanners
    if options.get("SSL/TLS"):
        status.info("🔒 Scanning SSL/TLS...")
        findings = run_ssl_scan(target_url)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"🔒 SSL scan done — {len(findings)} findings")

    if options.get("Headers"):
        status.info("📋 Scanning HTTP headers...")
        findings = run_headers_scan(urls, session)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"📋 Headers scan done — {len(findings)} findings")

    if options.get("Info Leakage"):
        status.info("🔍 Scanning for information leakage...")
        findings = run_info_leakage_scan(urls, session)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"🔍 Info leakage scan done — {len(findings)} findings")

    if options.get("CSRF"):
        status.info("🛡️ Scanning for CSRF vulnerabilities...")
        findings = run_csrf_scan(urls, session)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"🛡️ CSRF scan done — {len(findings)} findings")

    if options.get("SQL Injection"):
        status.info("💉 Scanning for SQL injection...")
        findings = run_sql_scan(urls, session)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"💉 SQLi scan done — {len(findings)} findings")

    if options.get("XSS"):
        status.info("⚡ Scanning for XSS vulnerabilities...")
        findings = run_xss_scan(urls, session)
        all_findings.extend(findings)
        current += step_size
        progress.progress(min(current, 90), text=f"⚡ XSS scan done — {len(findings)} findings")

    progress.progress(100, text="✅ Scan complete!")
    status.success(f"✅ Scan finished. {len(all_findings)} total findings.")

    return sort_findings(all_findings)


# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Scan Configuration")
    st.markdown("---")

    target_url = st.text_input(
        "🎯 Target URL",
        placeholder="https://example.com",
        help="Enter the full URL including http:// or https://"
    )

    max_urls = st.slider(
        "🕷️ Max URLs to Crawl",
        min_value=1,
        max_value=100,
        value=20,
        step=5,
        help="Limit the number of pages to scan"
    )

    st.markdown("### 🔬 Scan Modules")
    options = {
        "SSL/TLS": st.checkbox("🔒 SSL/TLS", value=True),
        "Headers": st.checkbox("📋 HTTP Headers", value=True),
        "Info Leakage": st.checkbox("🔍 Info Leakage", value=True),
        "CSRF": st.checkbox("🛡️ CSRF", value=True),
        "SQL Injection": st.checkbox("💉 SQL Injection", value=True),
        "XSS": st.checkbox("⚡ XSS", value=True),
    }

    st.markdown("---")
    scan_button = st.button("🚀 Start Scan", use_container_width=True, type="primary")

    st.markdown("---")
    st.markdown("### 📤 Export")
    export_format = st.selectbox("Format", ["JSON", "CSV"])


# ─────────────────────────────────────────────
# Main Content
# ─────────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ WebVulnScanner</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">OWASP-inspired Web Vulnerability Scanner</div>', unsafe_allow_html=True)

# ─── Tabs ───
tab_dashboard, tab_findings, tab_export, tab_about = st.tabs([
    "📊 Dashboard", "🔎 Findings", "📤 Export", "ℹ️ About"
])

# ─────────────────────────────────────────────
# Run Scan
# ─────────────────────────────────────────────
if scan_button:
    if not target_url:
        st.error("⚠️ Please enter a target URL.")
    elif not target_url.startswith(("http://", "https://")):
        st.error("⚠️ URL must start with http:// or https://")
    elif not any(options.values()):
        st.error("⚠️ Please select at least one scan module.")
    else:
        with st.spinner(""):
            findings = run_scan(target_url, options, max_urls)
        st.session_state["findings"] = findings
        st.session_state["scan_meta"] = {
            "target": target_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules": [k for k, v in options.items() if v],
            "urls_crawled": max_urls
        }


# ─────────────────────────────────────────────
# Dashboard Tab
# ─────────────────────────────────────────────
with tab_dashboard:
    if "findings" not in st.session_state:
        st.info("👈 Configure your scan in the sidebar and click **Start Scan**.")

        st.markdown("### 🔬 Available Scan Modules")
        col1, col2, col3 = st.columns(3)
        modules = [
            ("🔒 SSL/TLS", "Checks certificate validity, expiry, weak ciphers, and protocol versions."),
            ("📋 HTTP Headers", "Detects missing security headers like CSP, HSTS, X-Frame-Options."),
            ("🔍 Info Leakage", "Finds exposed secrets, sensitive files, stack traces, and debug info."),
            ("🛡️ CSRF", "Detects forms missing CSRF tokens or SameSite cookie attributes."),
            ("💉 SQL Injection", "Tests parameters for error-based and boolean SQL injection."),
            ("⚡ XSS", "Tests parameters for reflected cross-site scripting vulnerabilities."),
        ]
        for i, (name, desc) in enumerate(modules):
            col = [col1, col2, col3][i % 3]
            with col:
                st.markdown(f"**{name}**")
                st.caption(desc)
        st.stop()

    findings = st.session_state["findings"]
    meta = st.session_state.get("scan_meta", {})
    summary = build_summary(findings)

    # Scan metadata
    st.markdown(f"**🎯 Target:** `{meta.get('target', 'N/A')}`  |  "
                f"**🕐 Scanned:** {meta.get('timestamp', 'N/A')}  |  "
                f"**📦 Modules:** {', '.join(meta.get('modules', []))}")
    st.markdown("---")

    # Summary metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    metrics = [
        (col1, "🔴 Critical", summary["Critical"]),
        (col2, "🟠 High", summary["High"]),
        (col3, "🟡 Medium", summary["Medium"]),
        (col4, "🔵 Low", summary["Low"]),
        (col5, "⚪ Info", summary["Info"]),
        (col6, "📊 Total", summary["Total"]),
    ]
    for col, label, value in metrics:
        with col:
            st.metric(label, value)

    st.markdown("---")

    # Risk score
    risk_score = min(100, (
        summary["Critical"] * 40 +
        summary["High"] * 20 +
        summary["Medium"] * 10 +
        summary["Low"] * 5 +
        summary["Info"] * 1
    ))
    risk_label = (
        "🔴 Critical Risk" if risk_score >= 80 else
        "🟠 High Risk" if risk_score >= 50 else
        "🟡 Medium Risk" if risk_score >= 20 else
        "🟢 Low Risk"
    )
    st.markdown(f"### Risk Score: **{risk_score}/100** — {risk_label}")
    st.progress(risk_score / 100)

    st.markdown("---")

    # Findings by type chart
    if findings:
        st.markdown("### 📊 Findings by Type")
        type_counts = Counter(f.get("type", "Unknown") for f in findings)
        df_chart = pd.DataFrame(
            type_counts.items(), columns=["Type", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(df_chart.set_index("Type"))

        # Severity breakdown
        st.markdown("### 📈 Severity Breakdown")
        sev_df = pd.DataFrame([
            {"Severity": k, "Count": v}
            for k, v in summary.items() if k != "Total"
        ])
        st.bar_chart(sev_df.set_index("Severity"))


# ─────────────────────────────────────────────
# Findings Tab
# ─────────────────────────────────────────────
with tab_findings:
    if "findings" not in st.session_state or not st.session_state["findings"]:
        st.info("No findings yet. Run a scan first.")
    else:
        findings = st.session_state["findings"]

        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            sev_filter = st.multiselect(
                "Filter by Severity",
                ["Critical", "High", "Medium", "Low", "Info"],
                default=["Critical", "High", "Medium", "Low", "Info"]
            )
        with col2:
            types = list(set(f.get("type", "") for f in findings))
            type_filter = st.multiselect("Filter by Type", types, default=types)
        with col3:
            search = st.text_input("🔍 Search", placeholder="keyword...")

        # Apply filters
        filtered = [
            f for f in findings
            if f.get("severity", "Info") in sev_filter
            and f.get("type", "") in type_filter
            and (not search or search.lower() in json.dumps(f).lower())
        ]

        st.markdown(f"**Showing {len(filtered)} of {len(findings)} findings**")
        st.markdown("---")

        # Display findings
        for i, finding in enumerate(filtered):
            sev = finding.get("severity", "Info")
            icon = SEVERITY_COLORS.get(sev, "⚪")
            title = f"{icon} [{sev}] {finding.get('type', 'Unknown')}"

            with st.expander(title, expanded=(sev in ["Critical", "High"])):
                c1, c2 = st.columns([1, 3])
                with c1:
                    st.markdown(f"**Severity**")
                    st.markdown(severity_badge(sev), unsafe_allow_html=True)
                with c2:
                    st.markdown(f"**URL:** `{finding.get('url', 'N/A')}`")

                st.markdown(f"**📝 Detail:** {finding.get('detail', 'N/A')}")

                if finding.get("evidence"):
                    st.markdown("**🔬 Evidence:**")
                    st.code(finding.get("evidence", ""), language="text")

                if finding.get("recommendation"):
                    st.success(f"💡 **Recommendation:** {finding.get('recommendation', '')}")


# ─────────────────────────────────────────────
# Export Tab
# ─────────────────────────────────────────────
with tab_export:
    if "findings" not in st.session_state or not st.session_state["findings"]:
        st.info("No findings to export. Run a scan first.")
    else:
        findings = st.session_state["findings"]
        meta = st.session_state.get("scan_meta", {})

        st.markdown("### 📤 Export Scan Results")

        if export_format == "JSON":
            export_data = {
                "scan_metadata": meta,
                "summary": build_summary(findings),
                "findings": findings
            }
            json_str = json.dumps(export_data, indent=2)
            st.download_button(
                label="⬇️ Download JSON Report",
                data=json_str,
                file_name=f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
            st.code(json_str[:2000] + ("\n... (truncated)" if len(json_str) > 2000 else ""), language="json")

        elif export_format == "CSV":
            df = findings_to_df(findings)
            csv_str = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Download CSV Report",
                data=csv_str,
                file_name=f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
            st.dataframe(df, use_container_width=True)


# ─────────────────────────────────────────────
# About Tab
# ─────────────────────────────────────────────
with tab_about:
    st.markdown("""
    ## 🛡️ WebVulnScanner

    An OWASP ZAP-inspired web vulnerability scanner built with Python and Streamlit.

    ### 🔬 Scan Modules
    | Module | Description |
    |--------|-------------|
    | 🔒 SSL/TLS | Certificate validity, expiry, weak protocols/ciphers |
    | 📋 HTTP Headers | Missing/misconfigured security headers |
    | 🔍 Info Leakage | Secrets, sensitive files, debug info, error messages |
    | 🛡️ CSRF | Missing CSRF tokens, SameSite cookie issues |
    | 💉 SQL Injection | Error-based and boolean SQL injection |
    | ⚡ XSS | Reflected cross-site scripting |

    ### ⚠️ Disclaimer
    > This tool is intended for **authorized security testing only**.
    > Do not scan websites without explicit permission.
    > The authors are not responsible for misuse.

    ### 🛠️ Tech Stack
    - **Frontend:** Streamlit
    - **HTTP:** requests, urllib3
    - **Parsing:** BeautifulSoup4, re
    - **SSL:** ssl, socket, cryptography

    ### 📦 Version
    `v1.0.0` — Built for educational and professional security auditing.
    """)
