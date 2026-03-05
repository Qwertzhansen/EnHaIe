"""
NHI Discovery Tool - Streamlit Dashboard (CVSS-Modell v2)

Starten mit:
    streamlit run src/dashboard.py

Oder über das CLI:
    python -m src.cli scan --mock
    streamlit run src/dashboard.py
"""

from __future__ import annotations

import math
import os
import sys

import pandas as pd
import streamlit as st

# Projekt-Root zum Python-Pfad hinzufügen
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.database import (
    _DEFAULT_DB_PATH,
    get_latest_scan,
    get_nhi_trend,
    get_scan_history,
)


# ---------------------------------------------------------------------------
# Seiten-Konfiguration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="NHI Discovery Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    .risk-critical { color: #f38ba8; font-weight: bold; }
    .risk-high     { color: #fab387; font-weight: bold; }
    .risk-medium   { color: #f9e2af; font-weight: bold; }
    .risk-low      { color: #a6e3a1; font-weight: bold; }
    .cvss-formula {
        background-color: #1e1e2e;
        border-radius: 8px;
        padding: 14px 20px;
        font-family: monospace;
        font-size: 1.15em;
        text-align: center;
        margin: 10px 0 16px 0;
        letter-spacing: 0.03em;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

LEVEL_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
LEVEL_COLORS = {
    "CRITICAL": "#f38ba8",
    "HIGH":     "#fab387",
    "MEDIUM":   "#f9e2af",
    "LOW":      "#a6e3a1",
}
LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _fmt(val, digits: int = 2) -> str:
    """Formatiert einen float-Wert oder gibt '–' zurück."""
    try:
        f = float(val)
        if pd.isna(f):
            return "–"
        return f"{f:.{digits}f}"
    except (TypeError, ValueError):
        return "–"


def _notna(val) -> bool:
    """True wenn val ein gültiger numerischer Wert ist (nicht None/NaN)."""
    try:
        return not pd.isna(val)
    except (TypeError, ValueError):
        return val is not None


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🔐 NHI Discovery")
    st.caption("Non-Human Identity Scanner")
    st.divider()

    st.subheader("Aktionen")
    if st.button("🔄 Mock-Scan ausführen", use_container_width=True, type="primary"):
        with st.spinner("Scanne (Mock-Modus)..."):
            from src.cli import _get_mock_nhis
            from src.database import save_scan
            from src.risk_scoring import score_all
            nhis = _get_mock_nhis()
            results = score_all(nhis)
            save_scan(results, aws_account="123456789012 (Demo)")
        st.success("Scan abgeschlossen!")
        st.rerun()

    st.divider()
    st.subheader("IaC-Scan")
    iac_path_input = st.text_input(
        "Terraform-Verzeichnis",
        placeholder="z.B. tests/fixtures",
        help="Pfad zu einem Terraform-Verzeichnis oder einer .tf-Datei",
    )
    iac_btn_disabled = not bool(iac_path_input)
    if st.button("🔍 IaC scannen", use_container_width=True, disabled=iac_btn_disabled):
        if os.path.exists(iac_path_input):
            with st.spinner("Analysiere Terraform-Dateien..."):
                from src.iac_scanner import generate_report as _iac_report
                _res = _iac_report(iac_path_input)
            st.session_state["iac_result"] = _res
            n = len(_res.findings)
            st.success(f"Fertig: {_res.files_scanned} Datei(en), {n} Finding(s)")
        else:
            st.error(f"Pfad nicht gefunden: {iac_path_input}")

    st.divider()
    st.caption(f"DB: `{os.path.basename(_DEFAULT_DB_PATH)}`")
    st.divider()
    st.subheader("Risk Level")
    st.markdown("""
🔴 **CRITICAL** 80–100
🟠 **HIGH** 60–79
🟡 **MEDIUM** 40–59
🟢 **LOW** 0–39
""")


# ---------------------------------------------------------------------------
# Daten laden
# ---------------------------------------------------------------------------

latest = get_latest_scan()
history = get_scan_history()

if not latest:
    st.title("🔐 NHI Discovery Tool")
    st.warning(
        "Noch keine Scans vorhanden. "
        "Klicke auf **Mock-Scan ausführen** in der Sidebar oder führe "
        "`python -m src.cli scan --mock` aus."
    )
    st.stop()

scan_meta = latest["scan"]
nhis_raw  = latest["nhis"]

ts      = scan_meta["timestamp"][:19].replace("T", " ")
account = scan_meta.get("aws_account") or "Unbekannt"

df = pd.DataFrame(nhis_raw)
if df.empty:
    st.warning("Scan enthält keine NHIs.")
    st.stop()

# Abgeleitete Spalten
df["top_recommendation"] = df["recommendations"].apply(
    lambda x: x[0] if isinstance(x, list) and x else "–"
)
df["policies_str"] = df["policies"].apply(
    lambda x: ", ".join(x) if isinstance(x, list) else str(x or "–")
)
df["risk_order"] = df["risk_level"].map(LEVEL_ORDER)
df = df.sort_values(["risk_order", "risk_score"], ascending=[True, False])

# CVSS-Spalten sicherstellen
for _col in ["likelihood", "impact", "exposure", "vulnerability",
             "attack_vector", "privilege_level", "data_sensitivity", "blast_radius"]:
    if _col not in df.columns:
        df[_col] = None


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🔐 NHI Discovery Tool")
st.caption(
    f"**Letzter Scan:** {ts}  |  **Account:** {account}  |  "
    f"**Scans gesamt:** {len(history)}"
)
st.divider()


# ---------------------------------------------------------------------------
# KPI-Karten
# ---------------------------------------------------------------------------

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

delta_crit = None
if len(history) >= 2:
    delta_crit = scan_meta["critical_count"] - history[1]["critical_count"]

kpi1.metric("Gesamt NHIs",  scan_meta["total_nhis"])
kpi2.metric("🔴 CRITICAL",  scan_meta["critical_count"],
            delta=delta_crit, delta_color="inverse")
kpi3.metric("🟠 HIGH",      scan_meta["high_count"])
kpi4.metric("🟡 MEDIUM",    scan_meta["medium_count"])
kpi5.metric("🟢 LOW",       scan_meta["low_count"])

st.divider()


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_overview, tab_detail, tab_iac, tab_history = st.tabs([
    "📊 NHI Übersicht",
    "🔍 Detail-Ansicht",
    "📁 IaC Findings",
    "📈 Scan-History",
])


# ===========================================================================
# TAB 1 – NHI Übersicht
# ===========================================================================

with tab_overview:

    # --- Charts ---
    chart1, chart2 = st.columns(2)

    with chart1:
        st.subheader("Verteilung nach Risk Level")
        try:
            import plotly.express as px
            rc = df["risk_level"].value_counts().reset_index()
            rc.columns = ["Risk Level", "Anzahl"]
            fig_pie = px.pie(
                rc, names="Risk Level", values="Anzahl",
                color="Risk Level", color_discrete_map=LEVEL_COLORS, hole=0.4,
            )
            fig_pie.update_layout(
                showlegend=True,
                margin=dict(t=0, b=0, l=0, r=0),
                height=280,
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        except ImportError:
            st.bar_chart(df["risk_level"].value_counts())

    with chart2:
        st.subheader("Top 10 riskanteste NHIs")
        try:
            import plotly.express as px
            top10 = df.nlargest(10, "risk_score")[["name", "risk_score", "risk_level"]].copy()
            top10["label"] = top10["name"].apply(lambda n: n[:28] + "…" if len(n) > 28 else n)
            fig_bar = px.bar(
                top10, x="risk_score", y="label", orientation="h",
                color="risk_level", color_discrete_map=LEVEL_COLORS,
                text="risk_score", range_x=[0, 100],
            )
            fig_bar.update_layout(
                showlegend=False,
                margin=dict(t=0, b=0, l=0, r=0),
                height=280,
                xaxis_title="Risk Score",
                yaxis_title="",
                yaxis={"categoryorder": "total ascending"},
            )
            fig_bar.update_traces(textposition="outside")
            st.plotly_chart(fig_bar, use_container_width=True)
        except ImportError:
            st.bar_chart(df.nlargest(10, "risk_score").set_index("name")["risk_score"])

    st.divider()

    # --- Filter ---
    fc1, fc2, fc3 = st.columns([2, 2, 3])
    with fc1:
        level_filter = st.multiselect(
            "Risk Level",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )
    with fc2:
        type_filter = st.multiselect(
            "Typ", df["type"].unique().tolist(),
            default=df["type"].unique().tolist(),
        )
    with fc3:
        name_filter = st.text_input("NHI-Name filtern", placeholder="z.B. svc-")

    filtered = df[df["risk_level"].isin(level_filter) & df["type"].isin(type_filter)]
    if name_filter:
        filtered = filtered[filtered["name"].str.contains(name_filter, case=False)]

    # --- Haupttabelle ---
    col_map = {
        "name":               "NHI Name",
        "type":               "Typ",
        "risk_score":         "Score",
        "risk_level":         "Risk Level",
        "likelihood":         "Likelihood",
        "impact":             "Impact",
        "top_recommendation": "Top-Empfehlung",
    }
    avail = [c for c in col_map if c in filtered.columns]
    tbl = filtered[avail].copy().rename(columns=col_map)
    tbl["Typ"] = tbl["Typ"].str.replace("IAM_", "")
    tbl["Risk Level"] = tbl["Risk Level"].apply(lambda l: f"{LEVEL_ICON.get(l,'')} {l}")

    for col in ["Likelihood", "Impact"]:
        if col in tbl.columns:
            tbl[col] = tbl[col].apply(_fmt)

    st.dataframe(
        tbl,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score", min_value=0, max_value=100, format="%d",
            ),
            "Top-Empfehlung": st.column_config.TextColumn("Top-Empfehlung", width="large"),
        },
    )
    st.caption(f"{len(filtered)} von {len(df)} NHIs angezeigt")


# ===========================================================================
# TAB 2 – Detail-Ansicht
# ===========================================================================

with tab_detail:
    nhi_names = df["name"].tolist()
    sel_name  = st.selectbox("NHI auswählen:", nhi_names, key="detail_select")

    if sel_name:
        row   = df[df["name"] == sel_name].iloc[0]
        level = row["risk_level"]
        score = int(row["risk_score"])
        L     = row.get("likelihood")
        I     = row.get("impact")

        det1, det2 = st.columns([1, 2])

        # --- Linke Spalte: Kurzinfo ---
        with det1:
            st.markdown(f"### {LEVEL_ICON.get(level, '')} {sel_name}")
            st.metric("Risk Score", f"{score}/100")
            st.progress(score / 100)
            st.markdown(f"**Typ:** {row['type'].replace('IAM_', '')}")

            age = row.get("age_days")
            st.markdown(f"**Alter:** {age if _notna(age) else '–'} Tage")

            unused = row.get("days_since_last_used")
            unused_txt = "Nie benutzt" if not _notna(unused) else f"{int(unused)} Tage"
            st.markdown(f"**Inaktiv seit:** {unused_txt}")

            key_age = row.get("access_key_age_days")
            if _notna(key_age):
                st.markdown(f"**Access Key Alter:** {int(key_age)} Tage")

            policies = row.get("policies")
            if isinstance(policies, list) and policies:
                st.markdown("**Policies:**")
                for p in policies:
                    st.markdown(f"- `{p}`")

        # --- Rechte Spalte: CVSS Breakdown ---
        with det2:
            # Formel
            if _notna(L) and _notna(I):
                calc = round(math.sqrt(float(L) * float(I)) * 100)
                st.markdown(
                    f'<div class="cvss-formula">'
                    f'sqrt({float(L):.2f} &times; {float(I):.2f}) &times; 100 '
                    f'= <b>{calc}</b>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("#### LIKELIHOOD " + (_fmt(L) if _notna(L) else ""))

            exp_v  = row.get("exposure")
            vuln_v = row.get("vulnerability")
            av_v   = row.get("attack_vector")

            likelihood_df = pd.DataFrame({
                "Komponente": ["Exposure", "Vulnerability", "Attack Vector"],
                "Bereich":    ["0–0.4",    "0–0.3",         "0–0.2"],
                "Wert":       [_fmt(exp_v), _fmt(vuln_v),   _fmt(av_v)],
            })
            st.dataframe(likelihood_df, use_container_width=True, hide_index=True)

            st.markdown("#### IMPACT " + (_fmt(I) if _notna(I) else ""))

            priv_v  = row.get("privilege_level")
            sens_v  = row.get("data_sensitivity")
            blast_v = row.get("blast_radius")

            impact_df = pd.DataFrame({
                "Komponente": ["Privilege Level", "Data Sensitivity", "Blast Radius"],
                "Bereich":    ["0–0.5",           "0–0.3",           "0–0.2"],
                "Wert":       [_fmt(priv_v),       _fmt(sens_v),      _fmt(blast_v)],
            })
            st.dataframe(impact_df, use_container_width=True, hide_index=True)

        # --- Findings und Empfehlungen ---
        findings = row.get("findings")
        if isinstance(findings, list) and findings:
            with st.expander("⚠️ Findings", expanded=True):
                for f in findings:
                    st.markdown(f"- {f}")

        recs = row.get("recommendations")
        if isinstance(recs, list) and recs:
            with st.expander("💡 Empfehlungen", expanded=True):
                for r in recs:
                    st.markdown(f"- {r}")

        # --- Trend ---
        trend = get_nhi_trend(sel_name)
        if len(trend) > 1:
            st.divider()
            st.markdown("**Risk Score Trend:**")
            trend_df = pd.DataFrame(trend)
            trend_df["scan_timestamp"] = pd.to_datetime(trend_df["scan_timestamp"])
            trend_df = trend_df.rename(
                columns={"scan_timestamp": "Zeitstempel", "risk_score": "Risk Score"}
            )
            st.line_chart(trend_df.set_index("Zeitstempel")["Risk Score"])


# ===========================================================================
# TAB 3 – IaC Findings
# ===========================================================================

with tab_iac:
    st.subheader("Terraform IaC-Scan Ergebnisse")

    iac_result = st.session_state.get("iac_result")

    if iac_result is None:
        st.info(
            "Noch kein IaC-Scan durchgeführt. "
            "Gib in der **Sidebar** einen Terraform-Pfad ein und klicke auf **IaC scannen**."
        )
        st.markdown("""
**Beispiel:**
```bash
# Sidebar → Terraform-Verzeichnis: tests/fixtures
# → scannt tests/fixtures/sample.tf
```
        """)
    else:
        # KPI-Zeile
        iac1, iac2, iac3, iac4 = st.columns(4)
        iac1.metric("Dateien gescannt", iac_result.files_scanned)
        iac2.metric("🔴 CRITICAL",      iac_result.critical_count)
        iac3.metric("🟠 HIGH",          iac_result.high_count)
        iac4.metric("🟡 MEDIUM",        iac_result.medium_count)

        if not iac_result.findings:
            st.success("✅ Keine Sicherheitsprobleme gefunden!")
        else:
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
            sorted_f = sorted(iac_result.findings, key=lambda f: sev_rank.get(f.severity, 9))

            rows = []
            for f in sorted_f:
                line_info = f" (Zeile {f.line})" if f.line else ""
                rows.append({
                    "Severity":   f"{LEVEL_ICON.get(f.severity, '⚪')} {f.severity}",
                    "Ressource":  f.resource,
                    "Problem":    f.issue,
                    "Empfehlung": f.recommendation,
                    "Datei":      os.path.basename(f.file) + line_info,
                })

            iac_df = pd.DataFrame(rows)
            st.dataframe(
                iac_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Problem":    st.column_config.TextColumn("Problem",    width="large"),
                    "Empfehlung": st.column_config.TextColumn("Empfehlung", width="large"),
                },
            )
            st.caption(f"Gesamt: {len(iac_result.findings)} Findings")


# ===========================================================================
# TAB 4 – Scan-History
# ===========================================================================

with tab_history:
    if len(history) <= 1:
        st.info("Mindestens 2 Scans nötig um einen Verlauf anzuzeigen.")
    else:
        st.subheader("Risk-Level-Entwicklung über Zeit")
        hist_df = pd.DataFrame(history)
        hist_df["timestamp"] = pd.to_datetime(hist_df["timestamp"])
        hist_df = hist_df.sort_values("timestamp")

        try:
            import plotly.graph_objects as go

            fig_hist = go.Figure()
            for col, color in [
                ("critical_count", "#f38ba8"),
                ("high_count",     "#fab387"),
                ("medium_count",   "#f9e2af"),
                ("low_count",      "#a6e3a1"),
            ]:
                fig_hist.add_trace(go.Scatter(
                    x=hist_df["timestamp"],
                    y=hist_df[col],
                    name=col.replace("_count", "").upper(),
                    line=dict(color=color),
                    mode="lines+markers",
                ))
            fig_hist.update_layout(
                height=350,
                margin=dict(t=0, b=0, l=0, r=0),
                xaxis_title="Zeitstempel",
                yaxis_title="Anzahl NHIs",
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        except ImportError:
            st.line_chart(
                hist_df.set_index("timestamp")[
                    ["critical_count", "high_count", "medium_count", "low_count"]
                ]
            )

        st.divider()
        st.subheader("Alle Scans")
        hist_tbl = hist_df[
            ["timestamp", "aws_account", "total_nhis",
             "critical_count", "high_count", "medium_count", "low_count"]
        ].copy()
        hist_tbl.columns = ["Zeitstempel", "Account", "Total", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        hist_tbl["Zeitstempel"] = hist_tbl["Zeitstempel"].dt.strftime("%Y-%m-%d %H:%M:%S")
        st.dataframe(hist_tbl, use_container_width=True, hide_index=True)
