"""
Interactive Plotly Chart Components for IntelAssist AI.
Renders IOC distribution donuts, risk gauges, log timeline activity, and threat severity charts.
"""

from typing import List, Dict, Any
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# SOC Dark Theme Layout Settings
DARK_THEME_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Plus Jakarta Sans, sans-serif", color="#cbd5e1", size=11),
    margin=dict(l=20, r=20, t=35, b=20),
)

def render_doc_distribution_chart(doc_type_counts: Dict[str, int]):
    """Render horizontal bar chart for ingested document format distribution."""
    if not doc_type_counts:
        return

    labels = list(doc_type_counts.keys())
    values = list(doc_type_counts.values())

    df = pd.DataFrame({"Format": labels, "Count": values})

    fig = px.bar(
        df,
        x="Count",
        y="Format",
        orientation="h",
        color="Format",
        color_discrete_sequence=["#38bdf8", "#0284c7", "#f59e0b", "#a855f7", "#10b981"]
    )

    fig.update_layout(
        **DARK_THEME_LAYOUT,
        title=dict(text="<b>Ingested Artifact Formats</b>", font_size=13),
        showlegend=False,
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
        yaxis=dict(showgrid=False),
        height=250
    )
    st.plotly_chart(fig, use_container_width=True)

def render_ioc_distribution_chart(ioc_type_counts: Dict[str, int]):
    """Render a donut chart showing breakdown of extracted IOC types."""
    if not ioc_type_counts:
        return

    labels = list(ioc_type_counts.keys())
    values = list(ioc_type_counts.values())
    
    colors = ["#38bdf8", "#0284c7", "#f59e0b", "#ef4444", "#a855f7", "#10b981", "#64748b"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.62,
        marker=dict(colors=colors, line=dict(color="#080c14", width=2)),
        textinfo="label+value",
        textfont=dict(size=11, color="#ffffff"),
        hoverinfo="label+value+percent"
    )])

    total_iocs = sum(values)
    fig.update_layout(
        **DARK_THEME_LAYOUT,
        title=dict(text="<b>IOC Type Distribution</b>", font_size=13),
        showlegend=True,
        legend=dict(orientation="h", y=-0.15),
        annotations=[dict(
            text=f"<b>{total_iocs}</b><br><span style='font-size:10px; color:#94a3b8;'>Total IOCs</span>",
            x=0.5, y=0.5,
            font_size=15,
            showarrow=False,
            font_color="#ffffff"
        )],
        height=280
    )
    st.plotly_chart(fig, use_container_width=True)

def render_risk_gauge_chart(score: int, title: str = "Threat Risk Index"):
    """Render a semi-circular cyber risk gauge chart (0-100)."""
    if score >= 81:
        bar_color = "#ef4444"
        risk_label = "CRITICAL RISK"
    elif score >= 61:
        bar_color = "#f97316"
        risk_label = "HIGH RISK"
    elif score >= 41:
        bar_color = "#f59e0b"
        risk_label = "ELEVATED"
    elif score >= 21:
        bar_color = "#38bdf8"
        risk_label = "MEDIUM"
    else:
        bar_color = "#10b981"
        risk_label = "LOW RISK"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"<b>{title}</b><br><span style='font-size:12px; color:{bar_color}; font-weight:700;'>{risk_label}</span>", 'font': {'size': 14, 'color': '#f8fafc'}},
        number={'suffix': "/100", 'font': {'size': 26, 'color': '#ffffff', 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "rgba(255,255,255,0.2)"},
            'bar': {'color': bar_color, 'thickness': 0.28},
            'bgcolor': "rgba(15, 23, 42, 0.6)",
            'borderwidth': 1,
            'bordercolor': "rgba(56, 189, 248, 0.2)",
            'steps': [
                {'range': [0, 20], 'color': "rgba(16, 185, 129, 0.15)"},
                {'range': [20, 40], 'color': "rgba(56, 189, 248, 0.15)"},
                {'range': [40, 60], 'color': "rgba(245, 158, 11, 0.15)"},
                {'range': [60, 80], 'color': "rgba(249, 115, 22, 0.15)"},
                {'range': [80, 100], 'color': "rgba(239, 68, 68, 0.25)"}
            ]
        }
    ))

    fig.update_layout(
        **DARK_THEME_LAYOUT,
        height=240,
        margin=dict(l=25, r=25, t=45, b=20)
    )
    st.plotly_chart(fig, use_container_width=True)

def render_threat_severity_bar_chart(severity_counts: Dict[str, int]):
    """Render horizontal bar chart for threat severity distribution."""
    if not severity_counts:
        return

    order = ["Low", "Medium", "Elevated", "High", "Critical"]
    labels = [k for k in order if k in severity_counts]
    values = [severity_counts.get(k, 0) for k in labels]
    colors = ["#10b981", "#38bdf8", "#f59e0b", "#f97316", "#ef4444"]

    df = pd.DataFrame({"Severity": labels, "Count": values})

    fig = px.bar(
        df,
        x="Count",
        y="Severity",
        orientation="h",
        color="Severity",
        color_discrete_map={
            "Low": "#10b981",
            "Medium": "#38bdf8",
            "Elevated": "#f59e0b",
            "High": "#f97316",
            "Critical": "#ef4444"
        }
    )

    fig.update_layout(
        **DARK_THEME_LAYOUT,
        title=dict(text="<b>Threat Severity Breakdown</b>", font_size=13),
        showlegend=False,
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
        yaxis=dict(showgrid=False),
        height=250
    )
    st.plotly_chart(fig, use_container_width=True)

def render_timeline_activity_chart(timeline_events: List[Dict[str, Any]]):
    """Render a chronological activity spike bar chart for log events."""
    if not timeline_events:
        return

    df = pd.DataFrame(timeline_events)
    if "time" not in df.columns:
        return

    time_counts = df["time"].value_counts().reset_index()
    time_counts.columns = ["Time", "Events"]
    time_counts = time_counts.sort_values("Time")

    fig = px.bar(
        time_counts,
        x="Time",
        y="Events",
        title="<b>Suspicious Activity Timeline Density</b>",
        color="Events",
        color_continuous_scale=["#38bdf8", "#f59e0b", "#ef4444"]
    )

    fig.update_layout(
        **DARK_THEME_LAYOUT,
        coloraxis_showscale=False,
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)", tickangle=-30),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
        height=260
    )
    st.plotly_chart(fig, use_container_width=True)
