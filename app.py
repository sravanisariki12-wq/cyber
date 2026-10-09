"""CQ-M02 — Intelligent Malicious Domain Detector
Track 01 — AI-Powered Threat Detection

Production-ready Streamlit Application with Dark SOC UI Aesthetics, Real-time Analytics,
XAI Explainability, SQLite Persistence, and Multi-Provider Threat Intelligence.
"""

from __future__ import annotations
import io
import json
import os
import sys
from pathlib import Path
import datetime
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (
    APP_NAME,
    APP_VERSION,
    APP_TRACK,
    DEFAULT_RISK_THRESHOLD_LOW,
    DEFAULT_RISK_THRESHOLD_HIGH,
    RISK_CATEGORY_LOW,
    RISK_CATEGORY_REVIEW,
    RISK_CATEGORY_HIGH,
    VIRUSTOTAL_API_KEY,
    ALIENVAULT_OTX_API_KEY,
    DATA_DIR,
    REPORTS_DIR,
    EVALUATION_REPORT_PATH
)
from src.domain_parser import DomainParser
from src.feature_extractor import DomainFeatureExtractor
from src.validation import InputValidator
from src.inference import DomainInferenceEngine
from src.database import DatabaseManager
from src.history import InvestigationHistory
from src.threat_intelligence import ThreatIntelManager


# =============================================================================
# STREAMLIT CONFIGURATION & CUSTOM SOC THEME
# =============================================================================
st.set_page_config(
    page_title="CQ-M02 Malicious Domain Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC CSS styling
CUSTOM_CSS = """
<style>
    /* Dark SOC Theme Colors */
    :root {
        --soc-bg: #0b111e;
        --soc-card: #131c2e;
        --soc-card-border: #1e293b;
        --soc-accent: #00d2ff;
        --soc-accent-hover: #38bdf8;
        --soc-text: #e2e8f0;
        --soc-text-dim: #94a3b8;
        --soc-green: #10b981;
        --soc-amber: #f59e0b;
        --soc-red: #ef4444;
    }

    /* Main container styling */
    .stApp {
        background-color: var(--soc-bg);
        color: var(--soc-text);
    }

    /* Metric Card Component */
    .soc-card {
        background: linear-gradient(145deg, #131c2e, #111827);
        border: 1px solid var(--soc-card-border);
        border-radius: 10px;
        padding: 1.2rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .soc-card-highlight {
        border-left: 4px solid var(--soc-accent);
    }

    /* Badges */
    .soc-badge {
        display: inline-block;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-low {
        background-color: rgba(16, 185, 129, 0.15);
        color: var(--soc-green);
        border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .badge-review {
        background-color: rgba(245, 158, 11, 0.15);
        color: var(--soc-amber);
        border: 1px solid rgba(245, 158, 11, 0.4);
    }
    .badge-high {
        background-color: rgba(239, 68, 68, 0.15);
        color: var(--soc-red);
        border: 1px solid rgba(239, 68, 68, 0.4);
    }

    /* Header styling */
    .soc-header {
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 1.8rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #ffffff;
        margin-bottom: 0.2rem;
    }
    .soc-subheader {
        font-size: 0.95rem;
        color: var(--soc-text-dim);
        margin-bottom: 1.5rem;
    }

    /* Disclaimer box */
    .soc-disclaimer {
        background-color: rgba(30, 41, 59, 0.6);
        border-left: 3px solid #38bdf8;
        padding: 0.75rem 1rem;
        font-size: 0.82rem;
        color: #94a3b8;
        border-radius: 4px;
        margin-top: 1rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# =============================================================================
# SERVICE SINGLETONS & CACHING
# =============================================================================
@st.cache_resource
def get_inference_engine():
    return DomainInferenceEngine()

@st.cache_resource
def get_database_manager():
    return DatabaseManager()

@st.cache_resource
def get_history_repository():
    return InvestigationHistory(get_database_manager())

@st.cache_resource
def get_input_validator():
    return InputValidator()

@st.cache_resource
def get_threat_intel_manager():
    return ThreatIntelManager()


inference_engine = get_inference_engine()
db_manager = get_database_manager()
history_repo = get_history_repository()
validator = get_input_validator()
ti_manager = get_threat_intel_manager()


# =============================================================================
# SIDEBAR NAVIGATION
# =============================================================================
with st.sidebar:
    st.markdown("### 🛡️ **CQ-M02 DETECTOR**")
    st.caption(f"{APP_TRACK} • v{APP_VERSION}")
    st.divider()

    selected_nav = st.radio(
        "Navigation",
        [
            "📊 Overview Dashboard",
            "🔍 Analyze Domain",
            "📁 Bulk CSV Scan",
            "📋 Scan Results",
            "📜 Investigation History",
            "🌐 Threat Intelligence",
            "📈 Model Performance",
            "ℹ️ About the Project"
        ],
        index=0
    )

    st.divider()
    st.markdown("##### ⚙️ **Active Pipeline Models**")
    available_models = inference_engine.available_models
    if available_models:
        for m in available_models:
            st.markdown(f"- ✅ **{m}**")
    else:
        st.warning("No pre-trained models found. Train models in ML section or run fallback mode.")

    st.divider()
    st.markdown("##### 📡 **Threat Intelligence Feeds**")
    st.markdown("- 🟢 **Local IOC Threat Feed** (Active)")
    st.markdown(f"- {'🟢' if VIRUSTOTAL_API_KEY else '⚪'} **VirusTotal v3** ({'Configured' if VIRUSTOTAL_API_KEY else 'Offline'})")
    st.markdown(f"- {'🟢' if ALIENVAULT_OTX_API_KEY else '⚪'} **AlienVault OTX** ({'Configured' if ALIENVAULT_OTX_API_KEY else 'Offline'})")


# =============================================================================
# HELPER FUNCTIONS FOR RENDERING
# =============================================================================
def get_badge_html(category: str) -> str:
    if category == RISK_CATEGORY_HIGH:
        return f'<span class="soc-badge badge-high">🚨 {category}</span>'
    elif category == RISK_CATEGORY_REVIEW:
        return f'<span class="soc-badge badge-review">⚠️ {category}</span>'
    else:
        return f'<span class="soc-badge badge-low">🛡️ {category}</span>'


def render_metric_card(title: str, value: str | int | float, subtext: str = "", border_color: str = "#00d2ff"):
    st.markdown(
        f"""
        <div class="soc-card" style="border-left: 4px solid {border_color};">
            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">{title}</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff; margin: 0.2rem 0;">{value}</div>
            <div style="font-size: 0.8rem; color: #64748b;">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# =============================================================================
# 1. OVERVIEW DASHBOARD
# =============================================================================
if selected_nav == "📊 Overview Dashboard":
    st.markdown('<div class="soc-header">Security Operations Center — Overview Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Live telemetry, risk scoring aggregates, and diagnostic metrics from recorded domain investigations.</div>', unsafe_allow_html=True)

    metrics = history_repo.get_dashboard_metrics()
    total_scans = metrics["total_scans"]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric_card("Total Domains Scanned", total_scans, "All recorded queries", "#00d2ff")
    with col2:
        render_metric_card("High Risk Detections", metrics["high_risk_count"], "Action required", "#ef4444")
    with col3:
        render_metric_card("Requiring Review", metrics["review_count"], "Suspicious heuristics", "#f59e0b")
    with col4:
        render_metric_card("Low Risk / Benign", metrics["low_risk_count"], "Normal baseline", "#10b981")

    st.markdown("---")

    # Empty State Handling
    if total_scans == 0:
        st.info("💡 **No domain investigations recorded yet.** Start by analyzing a single domain or uploading a bulk CSV list.")
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("🚀 Run Demonstration Analysis (paypal-security-update.com)"):
                res = inference_engine.analyze_domain("paypal-security-update.com", model_name="Random Forest", check_threat_intel=True)
                if res["success"]:
                    record = res["assessment"].to_dict()
                    record["scan_type"] = "single"
                    db_manager.insert_scan_record(record)
                    st.rerun()
        with col_btn2:
            if st.button("🚀 Load Sample Dataset Scans (demo_upload.csv)"):
                sample_file = DATA_DIR / "demo_upload.csv"
                if sample_file.exists():
                    df_sample = pd.read_csv(sample_file)
                    valid_recs = [{"row": idx+1, "domain": d} for idx, d in enumerate(df_sample["domain"].dropna()) if validator.parser.parse(d).is_valid]
                    results = inference_engine.analyze_bulk(valid_recs[:10], check_threat_intel=True)
                    db_manager.insert_bulk_scan_records(results)
                    st.rerun()

    else:
        # Dashboard Charts
        row1_col1, row1_col2 = st.columns([1, 1])

        with row1_col1:
            st.markdown("##### 🎯 **Risk Category Distribution**")
            dist = metrics["risk_distribution"]
            dist_df = pd.DataFrame([
                {"Category": "Low Risk", "Count": dist["Low Risk"], "Color": "#10b981"},
                {"Category": "Needs Review", "Count": dist["Needs Review"], "Color": "#f59e0b"},
                {"Category": "High Risk", "Count": dist["High Risk"], "Color": "#ef4444"}
            ])
            fig_pie = px.pie(
                dist_df,
                values="Count",
                names="Category",
                color="Category",
                color_discrete_map={"Low Risk": "#10b981", "Needs Review": "#f59e0b", "High Risk": "#ef4444"},
                hole=0.55
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0"),
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with row1_col2:
            st.markdown("##### 🔬 **Model Evaluation Benchmark (Held-out Test Split)**")
            if EVALUATION_REPORT_PATH.exists():
                with open(EVALUATION_REPORT_PATH, "r", encoding="utf-8") as f:
                    eval_data = json.load(f)
                rf_metrics = eval_data.get("models", {}).get("Random Forest", {})
                
                ecol1, ecol2 = st.columns(2)
                with ecol1:
                    st.metric("Test Precision", f"{rf_metrics.get('precision', 1.0) * 100:.1f}%")
                    st.metric("Test F1-Score", f"{rf_metrics.get('f1_score', 1.0) * 100:.1f}%")
                with ecol2:
                    st.metric("Test Recall", f"{rf_metrics.get('recall', 1.0) * 100:.1f}%")
                    st.metric("PR-AUC", f"{rf_metrics.get('pr_auc', 1.0):.4f}")
                
                st.caption("Benchmark calculated on independent test domains. View full matrix in Model Performance.")
            else:
                st.info("Evaluation report not yet generated. Run evaluation script in Model Performance.")

        st.markdown("##### 🕒 **Recent Investigations**")
        recent_scans = metrics["recent_scans"]
        if recent_scans:
            table_rows = []
            for r in recent_scans:
                table_rows.append({
                    "ID": r["id"],
                    "Domain": r["domain"],
                    "Prediction": r["model_prediction"],
                    "Combined Score": f"{r['combined_risk_score']:.1f}",
                    "Category": r["risk_category"],
                    "Confidence": r["confidence_level"],
                    "Scan Type": r["scan_type"].upper(),
                    "Timestamp": r["created_at"]
                })
            df_recent = pd.DataFrame(table_rows)
            st.dataframe(df_recent, use_container_width=True, hide_index=True)


# =============================================================================
# 2. ANALYZE DOMAIN (SINGLE DOMAIN INVESTIGATION)
# =============================================================================
elif selected_nav == "🔍 Analyze Domain":
    st.markdown('<div class="soc-header">Single Domain Threat Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Evaluate any domain name or URL with lexical feature extraction, ML classification, and threat intelligence.</div>', unsafe_allow_html=True)

    # Initialize analysis state
    if "analysis_result" not in st.session_state:
        st.session_state["analysis_result"] = None
    if "current_scan_id" not in st.session_state:
        st.session_state["current_scan_id"] = None

    # Define callback before widget instantiation to safely update session state
    def set_domain_sample(domain_value: str):
        st.session_state["single_domain_input"] = domain_value
        st.session_state["analysis_result"] = None
        st.session_state["current_scan_id"] = None

    # Input row
    col_input, col_model, col_ti = st.columns([3, 2, 1.5])
    with col_input:
        domain_query = st.text_input(
            "Target Domain or URL",
            placeholder="e.g. login-paypal-security.xyz or https://secure.bank.com/auth",
            key="single_domain_input"
        )
    with col_model:
        selected_model = st.selectbox(
            "Classification Model",
            inference_engine.available_models or ["Random Forest (Baseline)"]
        )
    with col_ti:
        enable_ti = st.checkbox("Query Threat Intel", value=True, help="Check local threat feed and configured external APIs.")

    # Quick example buttons with on_click callbacks (executed prior to script rerun)
    st.markdown("<span style='font-size:0.85rem; color:#94a3b8;'>Quick test cases:</span>", unsafe_allow_html=True)
    btn_c1, btn_c2, btn_c3, btn_c4 = st.columns(4)
    with btn_c1:
        st.button(
            "📌 paypal-security-update.com",
            on_click=set_domain_sample,
            args=("paypal-security-update.com",),
            use_container_width=True
        )
    with btn_c2:
        st.button(
            "📌 secure-login-chase-bank.xyz",
            on_click=set_domain_sample,
            args=("secure-login-chase-bank.xyz",),
            use_container_width=True
        )
    with btn_c3:
        st.button(
            "📌 xk93jf8d2m0q1v9z.xyz (DGA)",
            on_click=set_domain_sample,
            args=("xk93jf8d2m0q1v9z.xyz",),
            use_container_width=True
        )
    with btn_c4:
        st.button(
            "📌 wikipedia.org (Benign)",
            on_click=set_domain_sample,
            args=("wikipedia.org",),
            use_container_width=True
        )

    analyze_clicked = st.button("🔎 Analyze Domain", type="primary", use_container_width=True)

    # Only run analysis when the Analyze Domain button is explicitly clicked
    if analyze_clicked:
        if not domain_query.strip():
            st.warning("Please enter a domain name or URL to analyze.")
            st.session_state["analysis_result"] = None
            st.session_state["current_scan_id"] = None
        else:
            with st.spinner("Extracting features, evaluating models, and querying threat intelligence..."):
                analysis = inference_engine.analyze_domain(
                    domain_query,
                    model_name=selected_model,
                    check_threat_intel=enable_ti
                )
                st.session_state["analysis_result"] = analysis
                if analysis.get("success"):
                    assessment = analysis["assessment"]
                    scan_dict = assessment.to_dict()
                    scan_dict["scan_type"] = "single"
                    st.session_state["current_scan_id"] = db_manager.insert_scan_record(scan_dict)
                else:
                    st.session_state["current_scan_id"] = None

    # Only display analysis details below once the analysis has been executed via button click
    if st.session_state.get("analysis_result") is not None:
        analysis = st.session_state["analysis_result"]
        scan_id = st.session_state.get("current_scan_id")

        if not analysis.get("success"):
            st.error(f"❌ Validation Error: {analysis.get('error')}")
        else:
            assessment = analysis["assessment"]
            parsed = analysis["parsed"]
            features = analysis["features"]
            explanations = analysis["explanations"]
            ti_results = analysis["threat_intel_results"]

            # =============================================================
            # Analysis Summary Header Banner
            # =============================================================
            st.markdown("---")
            badge_html = get_badge_html(assessment.risk_category)
            st.markdown(
                f"""
                <div class="soc-card soc-card-highlight" style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 0.85rem; color: #94a3b8;">INVESTIGATION TARGET</div>
                        <div style="font-size: 1.6rem; font-weight: 700; color: #ffffff;">{assessment.domain}</div>
                        <div style="font-size: 0.85rem; color: #64748b;">Record ID: #{scan_id} • Analyzed: {assessment.scan_timestamp}</div>
                    </div>
                    <div style="text-align: right;">
                        {badge_html}
                        <div style="font-size: 0.9rem; color: #cbd5e1; margin-top: 0.3rem;">Confidence: <b>{assessment.confidence_level}</b></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Score Metrics Row
            m_c1, m_c2, m_c3, m_c4 = st.columns(4)
            with m_c1:
                risk_color = "#ef4444" if assessment.combined_risk_score >= 70 else ("#f59e0b" if assessment.combined_risk_score >= 35 else "#10b981")
                render_metric_card("Combined Risk Score", f"{assessment.combined_risk_score:.1f} / 100", f"Category: {assessment.risk_category}", risk_color)
            with m_c2:
                render_metric_card(f"{assessment.model_name} Proba", f"{assessment.model_probability:.1f}%", f"Prediction: {assessment.model_prediction}", "#3b82f6")
            with m_c3:
                render_metric_card("Heuristic Score", f"{assessment.heuristic_score:.1f} / 100", f"{len(assessment.heuristics_triggered)} triggers flagged", "#8b5cf6")
            with m_c4:
                render_metric_card("Threat Intel Score", f"{assessment.threat_intel_score:.1f} / 100", f"{len(assessment.threat_intel_matches)} confirmed IOC matches", "#ec4899")

            # =============================================================
            # Detailed Analysis Tabs
            # =============================================================
            tab_reasons, tab_xai, tab_anatomy, tab_ti, tab_notes = st.tabs([
                "📋 Key Findings & Reasons",
                "🧠 Explainable AI (XAI)",
                "🔬 Domain Anatomy & Features",
                "📡 Threat Intelligence Evidence",
                "✍️ Analyst Notes"
            ])

            with tab_reasons:
                st.markdown("##### 📌 **Automated Diagnostic Findings**")
                for reason in assessment.reasons:
                    st.markdown(f"- 🔸 {reason}")

                if assessment.heuristics_triggered:
                    st.markdown("##### ⚠️ **Heuristic Indicators Triggered**")
                    for h in assessment.heuristics_triggered:
                        st.markdown(f"- 🚩 `{h}`")

                st.markdown(f'<div class="soc-disclaimer">{assessment.disclaimer}</div>', unsafe_allow_html=True)

            with tab_xai:
                st.markdown("##### 🧠 **Transparent Model Attribution**")
                st.caption(explanations.get("method", "Model Interpretation"))

                if "top_contributing_factors" in explanations:
                    factors = explanations["top_contributing_factors"]
                    if factors:
                        f_df = pd.DataFrame(factors)
                        fig_bar = px.bar(
                            f_df,
                            x="impact",
                            y="label",
                            orientation="h",
                            color="impact",
                            color_continuous_scale="Reds",
                            title="Top Feature Impacts on Suspicion Score"
                        )
                        fig_bar.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#e2e8f0"),
                            yaxis=dict(autorange="reversed"),
                            height=280
                        )
                        st.plotly_chart(fig_bar, use_container_width=True)

                        st.markdown("###### Detailed Factor Breakdown:")
                        for factor in factors:
                            st.markdown(f"- **{factor['label']}** (Value: `{factor['value']}`): {factor['description']}")
                    else:
                        st.info("Features are within normal baseline distributions.")

                elif "top_positive_ngrams" in explanations:
                    pos_ngrams = explanations.get("top_positive_ngrams", [])
                    neg_ngrams = explanations.get("top_negative_ngrams", [])
                    
                    col_pos, col_neg = st.columns(2)
                    with col_pos:
                        st.markdown("###### 🔴 Suspicious Character N-Grams (Pushed Score Up)")
                        if pos_ngrams:
                            for ng in pos_ngrams:
                                st.markdown(f"- `{ng['ngram']}` (weight: `+{ng['contribution']:.4f}`)")
                        else:
                            st.write("None identified.")
                    with col_neg:
                        st.markdown("###### 🟢 Benign Character N-Grams (Pushed Score Down)")
                        if neg_ngrams:
                            for ng in neg_ngrams:
                                st.markdown(f"- `{ng['ngram']}` (weight: `{ng['contribution']:.4f}`)")
                        else:
                            st.write("None identified.")

                st.caption(explanations.get("xai_disclaimer", ""))

            with tab_anatomy:
                st.markdown("##### 🔍 **Structural Decomposition**")
                a_c1, a_c2, a_c3 = st.columns(3)
                with a_c1:
                    st.markdown(f"**Normalized FQDN:** `{parsed.normalized_domain}`")
                    st.markdown(f"**Second-Level Domain (SLD):** `{parsed.domain_name}`")
                    st.markdown(f"**Subdomain:** `{parsed.subdomain or '[None]'}`")
                with a_c2:
                    st.markdown(f"**Public Suffix (TLD):** `.{parsed.suffix}`")
                    st.markdown(f"**Registered Domain:** `{parsed.registered_domain}`")
                    st.markdown(f"**Total Labels:** `{len(parsed.labels)}`")
                with a_c3:
                    st.markdown(f"**Is IP Address:** `{'Yes' if parsed.is_ip else 'No'}`")
                    st.markdown(f"**Is Punycode (IDN):** `{'Yes' if parsed.is_punycode else 'No'}`")
                    st.markdown(f"**Character Entropy:** `{features.get('shannon_entropy', 0.0):.3f}`")

                st.markdown("###### All Numerical Features:")
                feat_table = pd.DataFrame([features]).T.reset_index()
                feat_table.columns = ["Feature Name", "Value"]
                st.dataframe(feat_table, use_container_width=True, hide_index=True)

            with tab_ti:
                st.markdown("##### 📡 **External Intelligence Responses**")
                if not ti_results:
                    st.info("Threat intelligence querying was not enabled for this scan.")
                else:
                    for ti in ti_results:
                        with st.expander(f"{'🚨' if ti['is_malicious'] else '🛡️'} {ti['provider_name']} — Status: {ti['match_status']}", expanded=ti['is_malicious']):
                            st.markdown(f"- **Lookup Timestamp:** `{ti['lookup_timestamp']}`")
                            st.markdown(f"- **Detection Ratio / Indicator:** `{ti['detection_ratio'] or 'N/A'}`")
                            st.markdown(f"- **Cached Result:** `{'Yes' if ti['cached'] else 'No'}`")
                            if ti.get("tags"):
                                st.markdown(f"- **Tags:** {', '.join(ti['tags'])}")
                            if ti.get("error_message"):
                                st.warning(f"Provider Error: {ti['error_message']}")
                            if ti.get("details"):
                                st.json(ti["details"])

            with tab_notes:
                st.markdown("##### ✍️ **Analyst Investigation Notes**")
                current_notes = st.text_area("Add or update notes for this investigation record:", key="note_input_box")
                if st.button("Save Analyst Notes"):
                    if history_repo.update_analyst_notes(scan_id, current_notes):
                        st.success(f"Analyst notes updated for Scan ID #{scan_id}!")
                    else:
                        st.error("Failed to update notes.")


# =============================================================================
# 3. BULK CSV SCAN
# =============================================================================
elif selected_nav == "📁 Bulk CSV Scan":
    st.markdown('<div class="soc-header">Bulk Domain Dataset Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Upload CSV datasets of up to 50,000 domains with full input validation, deduplication, and anomaly reporting.</div>', unsafe_allow_html=True)

    col_up1, col_up2 = st.columns([3, 1])
    with col_up1:
        uploaded_file = st.file_uploader("Upload CSV File", type=["csv"], help="Maximum size: 25 MB")
    with col_up2:
        st.markdown("<div style='margin-top: 1.8rem;'></div>", unsafe_allow_html=True)
        use_demo = st.button("📂 Load Demo Sample File (demo_upload.csv)")

    raw_file_bytes = None
    if use_demo:
        demo_path = DATA_DIR / "demo_upload.csv"
        if demo_path.exists():
            with open(demo_path, "rb") as f:
                raw_file_bytes = f.read()
            st.success("Loaded bundled demo_upload.csv successfully!")
        else:
            st.error("demo_upload.csv not found. Generate demo dataset in ML pipeline.")
    elif uploaded_file:
        raw_file_bytes = uploaded_file.read()

    if raw_file_bytes:
        # Step 1: Validate and inspect dataset
        audit = validator.validate_and_parse_csv(raw_file_bytes)

        if not audit.get("success"):
            st.error(f"❌ Upload Failed: {audit.get('error')}")
        else:
            # Step 2: Show Audit Metrics
            st.markdown("##### 📊 **Dataset Validation Audit**")
            b_c1, b_c2, b_c3, b_c4, b_c5 = st.columns(5)
            with b_c1:
                render_metric_card("Total Rows", audit["total_rows"], "In uploaded CSV", "#00d2ff")
            with b_c2:
                render_metric_card("Valid Domains", audit["valid_count"], "Ready to analyze", "#10b981")
            with b_c3:
                render_metric_card("Duplicates", audit["duplicate_count"], "Deduplicated", "#f59e0b")
            with b_c4:
                render_metric_card("Malformed", audit["malformed_count"], "Invalid syntax", "#ef4444")
            with b_c5:
                render_metric_card("Empty Rows", audit["skipped_empty_count"], "Skipped rows", "#64748b")

            # Expanders for skipped and malformed rows (no silent discards)
            if audit["malformed_records"] or audit["duplicate_records"] or audit["skipped_empty_rows"]:
                with st.expander("⚠️ View Data Quality Anomalies (Detailed Audit)", expanded=False):
                    if audit["malformed_records"]:
                        st.markdown("###### Malformed Entries:")
                        st.dataframe(pd.DataFrame(audit["malformed_records"]), use_container_width=True)
                    if audit["duplicate_records"]:
                        st.markdown("###### Duplicate Entries (First instance retained):")
                        st.dataframe(pd.DataFrame(audit["duplicate_records"]), use_container_width=True)
                    if audit["skipped_empty_rows"]:
                        st.markdown(f"###### Skipped Empty Rows: Row numbers {audit['skipped_empty_rows'][:20]}...")

            # Step 3: Column selection and Model config
            col_target_col, col_bulk_model, col_bulk_ti = st.columns([2, 2, 1.5])
            with col_target_col:
                selected_col = st.selectbox(
                    "Domain Name Column",
                    audit["available_columns"],
                    index=audit["available_columns"].index(audit["target_column"])
                )
            with col_bulk_model:
                bulk_model = st.selectbox(
                    "Scanning Model",
                    inference_engine.available_models or ["Random Forest"]
                )
            with col_bulk_ti:
                bulk_ti = st.checkbox("Enable Threat Intel", value=False, help="May increase scan duration for large files.")

            if st.button("⚡ Start Batch Analysis", type="primary", use_container_width=True):
                valid_records = audit["valid_records"]
                progress_bar = st.progress(0.0)
                status_text = st.empty()

                total_valid = len(valid_records)
                chunk_size = 50
                all_results = []

                for start_idx in range(0, total_valid, chunk_size):
                    chunk = valid_records[start_idx : start_idx + chunk_size]
                    chunk_res = inference_engine.analyze_bulk(chunk, model_name=bulk_model, check_threat_intel=bulk_ti)
                    all_results.extend(chunk_res)
                    progress = min(1.0, (start_idx + len(chunk)) / total_valid)
                    progress_bar.progress(progress)
                    status_text.text(f"Analyzed {len(all_results)} of {total_valid} domains...")

                # Persist to database
                db_manager.insert_bulk_scan_records(all_results)
                progress_bar.progress(1.0)
                status_text.success(f"Batch scan completed! {len(all_results)} records analyzed and saved to database.")

                # Results Table
                st.markdown("##### 📋 **Batch Scan Results Preview**")
                res_df = pd.DataFrame(all_results)
                display_cols = ["row", "domain", "model_prediction", "model_probability", "combined_risk_score", "risk_category", "confidence_level"]
                st.dataframe(res_df[display_cols], use_container_width=True)

                # CSV Export
                csv_bytes = res_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "📥 Download Scan Report (CSV)",
                    data=csv_bytes,
                    file_name=f"cq_m02_bulk_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )


# =============================================================================
# 4. SCAN RESULTS
# =============================================================================
elif selected_nav == "📋 Scan Results":
    st.markdown('<div class="soc-header">Scan Results Repository</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Interactive analysis results browser with risk filtering, sorting, and reporting.</div>', unsafe_allow_html=True)

    filter_c1, filter_c2, filter_c3 = st.columns([2, 1.5, 1.5])
    with filter_c1:
        search_kw = st.text_input("Filter by Domain Substring", placeholder="e.g. paypal, xyz")
    with filter_c2:
        cat_filter = st.selectbox("Risk Category", ["All", RISK_CATEGORY_HIGH, RISK_CATEGORY_REVIEW, RISK_CATEGORY_LOW])
    with filter_c3:
        type_filter = st.selectbox("Scan Mode", ["All", "Single", "Bulk"])

    records = history_repo.search_investigations(
        domain_query=search_kw,
        risk_category=cat_filter,
        scan_type=type_filter,
        limit=500
    )

    if not records:
        st.info("No scan records match the current filter criteria.")
    else:
        df_export = history_repo.export_to_dataframe(records)
        
        # Risk Distribution in Results
        score_fig = px.histogram(
            df_export,
            x="Combined Risk Score",
            color="Risk Category",
            color_discrete_map={"Low Risk": "#10b981", "Needs Review": "#f59e0b", "High Risk": "#ef4444"},
            nbins=20,
            title="Combined Risk Score Distribution for Filtered Results"
        )
        score_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            height=260
        )
        st.plotly_chart(score_fig, use_container_width=True)

        st.dataframe(df_export, use_container_width=True, hide_index=True)

        csv_data = df_export.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Export Filtered Results to CSV",
            data=csv_data,
            file_name=f"cq_m02_scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


# =============================================================================
# 5. INVESTIGATION HISTORY
# =============================================================================
elif selected_nav == "📜 Investigation History":
    st.markdown('<div class="soc-header">Investigation Audit Trail & History</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Persistent SQLite audit log with analyst annotations and investigation management.</div>', unsafe_allow_html=True)

    h_c1, h_c2 = st.columns([3, 1])
    with h_c1:
        hist_query = st.text_input("Search Investigation Log", placeholder="Search domain...")
    with h_c2:
        hist_cat = st.selectbox("Filter Risk", ["All", RISK_CATEGORY_HIGH, RISK_CATEGORY_REVIEW, RISK_CATEGORY_LOW], key="hist_cat")

    records = history_repo.search_investigations(domain_query=hist_query, risk_category=hist_cat, limit=100)

    if not records:
        st.info("No investigations found.")
    else:
        for rec in records:
            with st.expander(f"#{rec['id']} • {rec['domain']} — {rec['risk_category']} (Score: {rec['combined_risk_score']:.1f})"):
                col_i1, col_i2 = st.columns(2)
                with col_i1:
                    st.markdown(f"**Model Prediction:** {rec['model_prediction']} ({rec['model_probability']:.1f}%)")
                    st.markdown(f"**Confidence:** {rec['confidence_level']}")
                    st.markdown(f"**Model Used:** {rec['model_name']}")
                    st.markdown(f"**Scan Type:** {rec['scan_type'].upper()}")
                    st.markdown(f"**Timestamp:** `{rec['created_at']}`")
                with col_i2:
                    st.markdown(f"**Heuristic Score:** {rec['heuristic_score']:.1f}")
                    st.markdown(f"**Threat Intel Score:** {rec['threat_intel_score']:.1f}")
                    if rec.get("analyst_notes"):
                        st.markdown(f"**Analyst Notes:** *{rec['analyst_notes']}*")

                st.markdown("**Diagnostic Findings:**")
                for rea in rec.get("reasons", []):
                    st.markdown(f"- {rea}")

                # Inline Note Update
                note_key = f"note_update_{rec['id']}"
                updated_note = st.text_input("Update Analyst Notes:", value=rec.get("analyst_notes", ""), key=note_key)
                if st.button(f"Save Notes for #{rec['id']}", key=f"btn_note_{rec['id']}"):
                    history_repo.update_analyst_notes(rec['id'], updated_note)
                    st.success("Note saved!")
                    st.rerun()

    st.divider()
    with st.expander("⚠️ Danger Zone: Clear History"):
        confirm_clear = st.checkbox("I confirm that I wish to permanently delete all investigation logs from SQLite.")
        if st.button("🗑️ Clear Entire History", type="secondary"):
            if confirm_clear:
                deleted_rows = history_repo.clear_all_history()
                st.success(f"History cleared ({deleted_rows} records purged).")
                st.rerun()
            else:
                st.error("Please check the confirmation box before deleting.")


# =============================================================================
# 6. THREAT INTELLIGENCE
# =============================================================================
elif selected_nav == "🌐 Threat Intelligence":
    st.markdown('<div class="soc-header">Threat Intelligence Integration</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Multi-provider threat feeds, reputation scoring, and offline IOC lookups.</div>', unsafe_allow_html=True)

    st.markdown("##### 📡 **Provider Status & Credentials**")
    ti_c1, ti_c2, ti_c3 = st.columns(3)
    with ti_c1:
        st.markdown(
            """
            <div class="soc-card" style="border-left: 4px solid #10b981;">
                <div style="font-weight:700; color:#fff;">Local Curated IOC Feed</div>
                <div style="color:#10b981; font-size:0.9rem; margin:0.3rem 0;">Status: Active (Built-in)</div>
                <div style="font-size:0.8rem; color:#94a3b8;">Deterministic offline feed for known phishing and malware domain indicators.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with ti_c2:
        vt_status = "Active" if VIRUSTOTAL_API_KEY else "Not Configured"
        vt_color = "#10b981" if VIRUSTOTAL_API_KEY else "#94a3b8"
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 4px solid {vt_color};">
                <div style="font-weight:700; color:#fff;">VirusTotal v3 API</div>
                <div style="color:{vt_color}; font-size:0.9rem; margin:0.3rem 0;">Status: {vt_status}</div>
                <div style="font-size:0.8rem; color:#94a3b8;">Queries 70+ antivirus engines and domain categorization databases. Set <code>VIRUSTOTAL_API_KEY</code> in <code>.env</code>.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with ti_c3:
        otx_status = "Active" if ALIENVAULT_OTX_API_KEY else "Not Configured"
        otx_color = "#10b981" if ALIENVAULT_OTX_API_KEY else "#94a3b8"
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 4px solid {otx_color};">
                <div style="font-weight:700; color:#fff;">AlienVault OTX API</div>
                <div style="color:{otx_color}; font-size:0.9rem; margin:0.3rem 0;">Status: {otx_status}</div>
                <div style="font-size:0.8rem; color:#94a3b8;">Crowdsourced threat pulse correlation. Set <code>ALIENVAULT_OTX_API_KEY</code> in <code>.env</code>.</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.markdown("##### 🔎 **Dedicated Threat Intel Lookup Tool**")
    ti_domain = st.text_input("Enter domain name for direct TI query", "paypal-security-update.com")
    if st.button("Query All Feeds"):
        with st.spinner("Querying threat feeds..."):
            ti_res = ti_manager.lookup_domain(ti_domain)
        for r in ti_res:
            with st.expander(f"{'🚨' if r.is_malicious else '🛡️'} {r.provider_name} — {r.match_status}", expanded=True):
                st.markdown(f"**Match Status:** `{r.match_status}`")
                st.markdown(f"**Is Malicious:** `{'Yes' if r.is_malicious else 'No'}`")
                st.markdown(f"**Detection Ratio / Pulses:** `{r.detection_ratio or 'N/A'}`")
                st.markdown(f"**Tags:** {r.tags}")
                st.markdown(f"**Timestamp:** `{r.lookup_timestamp}`")
                st.markdown(f"**Cached:** `{'Yes' if r.cached else 'No'}`")
                if r.error_message:
                    st.warning(f"Error: {r.error_message}")
                if r.details:
                    st.json(r.details)


# =============================================================================
# 7. MODEL PERFORMANCE
# =============================================================================
elif selected_nav == "📈 Model Performance":
    st.markdown('<div class="soc-header">Model Performance & Diagnostic Benchmarks</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Real evaluation metrics calculated from the independent held-out test split.</div>', unsafe_allow_html=True)

    if not EVALUATION_REPORT_PATH.exists():
        st.warning("Evaluation report not yet found. Click below to run the evaluation pipeline on the held-out test dataset.")
        if st.button("🚀 Run Model Evaluation"):
            with st.spinner("Evaluating models..."):
                from ml.evaluate_model import evaluate_all_models
                evaluate_all_models()
                st.rerun()
    else:
        with open(EVALUATION_REPORT_PATH, "r", encoding="utf-8") as f:
            eval_data = json.load(f)

        models_eval = eval_data.get("models", {})
        
        # Disclosure box
        st.markdown(
            f"""
            <div class="soc-disclaimer">
                <b>DATASET LIMITATION DISCLOSURE:</b> {eval_data.get('dataset_limitation_disclosure')}
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Comparison Table
        comp_rows = []
        for name, m in models_eval.items():
            cm = m.get("confusion_matrix", {})
            comp_rows.append({
                "Model": name,
                "Model Architecture": m.get("model_type", "ML Pipeline"),
                "Precision": f"{m.get('precision', 0.0) * 100:.2f}%",
                "Recall": f"{m.get('recall', 0.0) * 100:.2f}%",
                "F1-Score": f"{m.get('f1_score', 0.0) * 100:.2f}%",
                "PR-AUC": f"{m.get('pr_auc', 0.0):.4f}",
                "ROC-AUC": f"{m.get('roc_auc', 0.0):.4f}",
                "False Positives": cm.get("false_positives", 0),
                "False Negatives": cm.get("false_negatives", 0)
            })
        st.dataframe(pd.DataFrame(comp_rows), use_container_width=True, hide_index=True)

        # Performance Comparison Chart
        st.markdown("##### 📊 **Model Comparison Matrix**")
        chart_data = []
        for name, m in models_eval.items():
            chart_data.append({"Model": name, "Metric": "Precision", "Score": m.get("precision", 0.0)})
            chart_data.append({"Model": name, "Metric": "Recall", "Score": m.get("recall", 0.0)})
            chart_data.append({"Model": name, "Metric": "F1-Score", "Score": m.get("f1_score", 0.0)})

        fig_comp = px.bar(
            pd.DataFrame(chart_data),
            x="Metric",
            y="Score",
            color="Model",
            barmode="group",
            title="Precision, Recall, and F1 Comparison"
        )
        fig_comp.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            yaxis=dict(range=[0.8, 1.02]),
            height=300
        )
        st.plotly_chart(fig_comp, use_container_width=True)

        # Confusion Matrices
        st.markdown("##### 🧮 **Confusion Matrices (Held-out Test Split)**")
        cm_cols = st.columns(len(models_eval))
        for idx, (name, m) in enumerate(models_eval.items()):
            with cm_cols[idx]:
                cm = m.get("confusion_matrix", {})
                matrix_vals = [
                    [cm.get("true_negatives", 0), cm.get("false_positives", 0)],
                    [cm.get("false_negatives", 0), cm.get("true_positives", 0)]
                ]
                fig_cm = px.imshow(
                    matrix_vals,
                    labels=dict(x="Predicted", y="Actual", color="Samples"),
                    x=["Benign", "Malicious"],
                    y=["Benign", "Malicious"],
                    text_auto=True,
                    color_continuous_scale="Blues",
                    title=f"{name}"
                )
                fig_cm.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#e2e8f0"),
                    height=280
                )
                st.plotly_chart(fig_cm, use_container_width=True)

        # Feature Importance for Random Forest
        rf_meta = models_eval.get("Random Forest", {})
        top_feats = rf_meta.get("top_features", {})
        if top_feats:
            st.markdown("##### 🌟 **Global Feature Importance (Random Forest)**")
            f_imp_df = pd.DataFrame(list(top_feats.items())[:12], columns=["Feature", "Importance"])
            fig_imp = px.bar(
                f_imp_df,
                x="Importance",
                y="Feature",
                orientation="h",
                color="Importance",
                color_continuous_scale="Viridis",
                title="Top Features Influencing Random Forest Splits"
            )
            fig_imp.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0"),
                yaxis=dict(autorange="reversed"),
                height=350
            )
            st.plotly_chart(fig_imp, use_container_width=True)


# =============================================================================
# 8. ABOUT THE PROJECT
# =============================================================================
elif selected_nav == "ℹ️ About the Project":
    st.markdown('<div class="soc-header">CQ-M02 — Intelligent Malicious Domain Detector</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Project architecture, methodology, machine learning models, and security considerations.</div>', unsafe_allow_html=True)

    st.markdown(
        """
        ### 🎯 Problem Statement
        Security operations center (SOC) analysts and incident response teams are inundated daily with massive volumes of domain names 
        logged in proxy logs, DNS queries, firewall egress events, and threat feeds. Identifying which domains represent malicious 
        infrastructure (such as phishing portals, credential harvesters, command-and-control servers, or algorithmically generated domains) 
        without actively browsing or detonating untrusted links is a fundamental cybersecurity challenge.

        ---

        ### 🛡️ System Architecture & Workflow
        The system implements a defense-in-depth analytical pipeline:
        1. **Input Normalization & Parsing**: Cleans raw user strings and URLs, extracts hostnames, strips query paths and ports, and parses multi-label public suffixes via `tldextract`.
        2. **Multi-Faceted Feature Engineering**: Computes 23 lexical, structural, and statistical features including Shannon character entropy, vowel/consonant ratios, digit ratios, and brand typosquatting distance.
        3. **Machine Learning Pipeline**:
           - **Model A (Baseline)**: Balanced Random Forest trained on 23 extracted numerical signals.
           - **Model B (Text Specialist)**: Sub-word character n-gram (3-5 grams) TF-IDF vectorizer + Logistic Regression.
           - **Model C (Benchmark)**: Gradient Boosted Trees via XGBoost.
        4. **Explainable AI Layer (XAI)**: Provides human-interpretable feature attribution charts and character token explanations for every classification.
        5. **Threat Intelligence Layer**: Connects with VirusTotal v3, AlienVault OTX, and local curated threat feeds with responsible caching and timeouts.
        6. **Calibrated Risk Engine**: Combines ML probabilities, lexical heuristics, and confirmed threat intelligence into categorized risk levels (*Low Risk*, *Needs Review*, *High Risk*).
        7. **Persistent Investigation Ledger**: Automatically persists all queries and analyst notes to a thread-safe SQLite database.

        ---

        ### ⚖️ Operational Priorities & Security Controls
        - **Untrusted Input Handling**: The application treats all submitted strings as hostile. It never automatically navigates to, connects with, or downloads payloads from submitted domains.
        - **Decision-Support Classification**: The tool clearly distinguishes model predictions, heuristic indicators, and confirmed threat-intelligence evidence. Low-confidence predictions are never presented as definitive evidence of malware.
        - **Data Privacy & Secret Management**: Threat intelligence API credentials are read strictly from environment variables and never exposed to the client or written to database records.
        """
    )
