#!/usr/bin/env python3
"""
LogSentinel-Lite: Enterprise SOC Log Telemetry & Threat Detection Engine
Author: Sol Acunzos
Description: Professional enterprise-grade log analyzer and threat dashboard.
"""

from collections import Counter
import json
import re
import pandas as pd
import streamlit as st

# --- PAGE CONFIGURATION & ENTERPRISE SOC THEME ---
st.set_page_config(
    page_title="LogSentinel-Lite // Enterprise SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# DefectDojo-inspired Professional Enterprise Dark Theme CSS
st.markdown("""
    <style>
    .main {
        background-color: #0b0f19;
        color: #94a3b8;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    h1, h2, h3, h4 {
        color: #f8fafc;
        font-weight: 600;
        letter-spacing: -0.025em;
    }
    .stMetric {
        background-color: #111827;
        border: 1px solid #1f2937;
        padding: 15px;
        border-radius: 8px;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #0b0f19;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 6px;
        color: #94a3b8;
        padding: 10px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1f2937 !important;
        color: #38bdf8 !important;
        border-color: #38bdf8 !important;
    }
    </style>
""", unsafe_allow_html=True)

def parse_telemetry_logs(file_lines, threshold, active_rules):
    records = []
    
    patterns = {
        "SSH Brute Force": (re.compile(r"Failed password.*?from\s+(\d{1,3}(?:\.\d{1,3}){3})"), "Critical"),
        "Web 403 Scan": (re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?GET\s+(/admin/.*?)\s+HTTP/.*?\s+403'), "Medium"),
        "Multi-Auth / Credential": (re.compile(r"Accepted (?:password|publickey) for (\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})"), "High"),
        "Sudo Escalation Failure": (re.compile(r"sudo:.*?authentication failure.*?user=(\S+)"), "Medium"),
        "Web POST Brute Force": (re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?POST\s+/(?:login|signin|auth).*?\s+HTTP/.*?\s+(?:401|403)'), "Critical"),
        "HTTP 500 Server Error": (re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?HTTP/.*?\s+500'), "Medium"),
    }

    counters = {k: Counter() for k in patterns.keys()}
    daemon_count = 0
    daemon_pattern = re.compile(r"(?:fatal|Segmentation fault|Connection reset by peer|service failed|CRITICAL)", re.IGNORECASE)

    for raw_line in file_lines:
        line = raw_line.decode("utf-8", errors="ignore") if isinstance(raw_line, bytes) else raw_line
        
        if "ssh" in active_rules:
            m = patterns["SSH Brute Force"][0].search(line)
            if m: counters["SSH Brute Force"][m.group(1)] += 1
                
        if "web" in active_rules:
            m = patterns["Web 403 Scan"][0].search(line)
            if m: counters["Web 403 Scan"][m.group(1)] += 1

        if "success_login" in active_rules:
            m = patterns["Multi-Auth / Credential"][0].search(line)
            if m: counters["Multi-Auth / Credential"][m.group(2)] += 1

        if "sudo_fail" in active_rules:
            m = patterns["Sudo Escalation Failure"][0].search(line)
            if m: counters["Sudo Escalation Failure"][m.group(1)] += 1

        if "web_login" in active_rules:
            m = patterns["Web POST Brute Force"][0].search(line)
            if m: counters["Web POST Brute Force"][m.group(1)] += 1

        if "server_error" in active_rules:
            m = patterns["HTTP 500 Server Error"][0].search(line)
            if m: counters["HTTP 500 Server Error"][m.group(1)] += 1

        if "daemon_crash" in active_rules:
            if daemon_pattern.search(line):
                daemon_count += 1

    dataset = []
    for attack_type, ip_counts in counters.items():
        severity = patterns[attack_type][1]
        for target, count in ip_counts.items():
            if count >= threshold:
                dataset.append({
                    "Severity": severity,
                    "Threat Type": attack_type,
                    "Source / Target": target,
                    "Event Count": count,
                    "Status": "Open / Active"
                })

    if daemon_count >= threshold:
        dataset.append({
            "Severity": "High",
            "Threat Type": "System Daemons / Crashes",
            "Source / Target": "Kernel / Services",
            "Event Count": daemon_count,
            "Status": "Open / Active"
        })

    return pd.DataFrame(dataset)

# --- SIDEBAR CONFIGURATION ---
with st.sidebar:
    st.markdown("### 🛡️ PLATFORM CONTROLS")
    st.markdown("---")
    threshold_limit = st.slider("Finding Threshold", min_value=1, max_value=10, value=3)
    
    st.markdown("#### Enabled Heuristics")
    r_ssh = st.checkbox("SSH Brute Force", value=True)
    r_web = st.checkbox("Web Forbidden (403)", value=True)
    r_cred = st.checkbox("Multi-Auth / Credentials", value=True)
    r_sudo = st.checkbox("Privilege Escalation (Sudo)", value=True)
    r_wlogin = st.checkbox("Web Login Brute Force", value=True)
    r_err500 = st.checkbox("HTTP 500 Errors", value=True)
    r_daemon = st.checkbox("Daemon / Service Crashes", value=True)

active_rules = []
if r_ssh: active_rules.append("ssh")
if r_web: active_rules.append("web")
if r_cred: active_rules.append("success_login")
if r_sudo: active_rules.append("sudo_fail")
if r_wlogin: active_rules.append("web_login")
if r_err500: active_rules.append("server_error")
if r_daemon: active_rules.append("daemon_crash")

# --- MAIN DASHBOARD VIEW ---
st.markdown("# 🛡️ LogSentinel-Lite // Enterprise Dashboard")
st.markdown("`Platform State: Operational` | `Telemetry Engine: Active` | `Compliance: SOC 2 / ISO 27001 Ready`")
st.markdown("---")

uploaded_log = st.file_uploader("Upload Telemetry Stream (auth.log, access.log, syslog)", type=["log", "txt"])

if uploaded_log:
    lines = uploaded_log.readlines()
    df_results = parse_telemetry_logs(lines, threshold_limit, active_rules)
    
    total_findings = len(df_results)
    critical_findings = len(df_results[df_results["Severity"] == "Critical"]) if not df_results.empty else 0
    high_findings = len(df_results[df_results["Severity"] == "High"]) if not df_results.empty else 0
    medium_findings = len(df_results[df_results["Severity"] == "Medium"]) if not df_results.empty else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Findings", total_findings)
    col2.metric("Critical Risk", critical_findings)
    col3.metric("High Risk", high_findings)
    col4.metric("Medium Risk", medium_findings)
    
    st.markdown("### 📋 Active Security Findings")
    
    if not df_results.empty:
        st.dataframe(
            df_results,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Threat Type": st.column_config.TextColumn("Vulnerability / Threat Vector", width="medium"),
                "Source / Target": st.column_config.TextColumn("Source IP / Entity", width="medium"),
                "Event Count": st.column_config.NumberColumn("Occurrences", width="small"),
                "Status": st.column_config.TextColumn("Status", width="small")
            }
        )
        st.markdown("---")
        
        col_export1, col_export2 = st.columns([3, 1])
        with col_export1:
            st.info(f"Analysis completed successfully on `{uploaded_log.name}`.")
        with col_export2:
            json_report = df_results.to_json(orient="records", indent=4)
            st.download_button(
                label="📥 Export Report (JSON)",
                data=json_report,
                file_name="logsentinel_enterprise_report.json",
                mime="application/json"
            )
    else:
        st.success("✅ Clean Telemetry: No active security findings surpassed the configured threshold.")
else:
    st.markdown("""
        <div style='background-color: #111827; border: 1px dashed #374151; padding: 40px; text-align: center; border-radius: 8px; margin-top: 20px;'>
            <h3 style='color: #94a3b8; margin-bottom: 10px;'>No Log Telemetry Loaded</h3>
            <p style='color: #6b7280;'>Upload a server log file above to initialize threat parsing and populate findings.</p>
        </div>
    """, unsafe_allow_html=True)
