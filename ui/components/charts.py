"""
LynxMap - Modular Chart Definitions
Reusable chart components for visualizations
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


def create_bar_chart(data, x, y, title="", color_scale="Viridis"):
    """Create a styled bar chart"""
    fig = px.bar(data, x=x, y=y, color=y, color_continuous_scale=color_scale, title=title)
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis_tickangle=-45,
        height=400,
    )
    return fig


def create_sunburst(ids, labels, parents, values, colors=None, title=""):
    """Create a styled sunburst chart"""
    fig = go.Figure(go.Sunburst(
        ids=ids,
        labels=labels,
        parents=parents,
        values=values,
        marker=dict(colors=colors, line=dict(color="#1a1a2e", width=2)) if colors else None,
        branchvalues="total",
        maxdepth=3
    ))
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=50, l=50, r=50, b=50),
        height=600,
        title=dict(text=title, font=dict(size=20, color="white"), x=0.5)
    )
    return fig


def create_gauge(value, title="Risk Score", reference=50):
    """Create a risk gauge chart"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        delta={"reference": reference, "increasing": {"color": "red"}},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "orange"},
            "steps": [
                {"range": [0, 30], "color": "green"},
                {"range": [30, 70], "color": "yellow"},
                {"range": [70, 100], "color": "red"}
            ],
            "threshold": {"line": {"color": "white", "width": 4}, "thickness": 0.75, "value": value}
        },
        title={"text": title, "font": {"size": 24, "color": "white"}}
    ))
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
    return fig
