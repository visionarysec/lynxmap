"""
LynxMap - Home Page (Dashboard Overview)
Displays asset inventory summary with bar charts and data tables from database
"""

import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import sys
from pathlib import Path

# Add parent directory to path for database import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import get_asset_summary, get_compartment_summary, get_region_summary, get_total_asset_count, get_all_assets, init_database

# Register this page
dash.register_page(__name__, path="/", name="Home", title="LynxMap - Dashboard")

# Initialize database on import
init_database()

# Asset type display names and icons
ASSET_TYPE_CONFIG = {
    "vm": {"label": "Virtual Machines", "icon": "fa-server", "color": "primary"},
    "vnic": {"label": "VNICs", "icon": "fa-network-wired", "color": "info"},
    "bucket": {"label": "Storage Buckets", "icon": "fa-database", "color": "warning"},
    "iam": {"label": "IAM Policies", "icon": "fa-users-cog", "color": "danger"},
    "lb": {"label": "Load Balancers", "icon": "fa-balance-scale", "color": "success"},
}


def create_asset_summary_cards():
    """Create summary cards for each asset category from database"""
    asset_counts = get_asset_summary()
    cards = []
    
    for asset_type, count in asset_counts.items():
        config = ASSET_TYPE_CONFIG.get(asset_type, {
            "label": asset_type.upper(),
            "icon": "fa-cube",
            "color": "secondary"
        })
        
        card = dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className=f"fas {config['icon']} fa-2x text-{config['color']}"),
                    ], className="mb-2"),
                    html.H5(config['label'], className="card-title mb-1"),
                    html.H2(f"{count:,}", className="text-white mb-1"),
                    html.Small(f"{asset_type} resources", className="text-muted"),
                ])
            ], className="bg-dark border-0 h-100 asset-card")
        ], lg=2, md=4, sm=6, className="mb-3")
        cards.append(card)
    
    return cards


def create_asset_distribution_chart():
    """Create bar chart showing asset distribution from database"""
    asset_counts = get_asset_summary()
    
    # Map to display labels
    labels = []
    counts = []
    colors = []
    
    # New color palette: Deep Navy Teal
    color_map = {
        "vm": "#5F9598",       # Muted teal (primary accent)
        "vnic": "#7DB0B3",     # Light teal
        "bucket": "#E8B84A",   # Warm gold
        "iam": "#E85A5A",      # Coral red
        "lb": "#4CAF7A"        # Soft green
    }
    
    for asset_type, count in asset_counts.items():
        config = ASSET_TYPE_CONFIG.get(asset_type, {"label": asset_type.upper()})
        labels.append(config['label'])
        counts.append(count)
        colors.append(color_map.get(asset_type, "#6c757d"))
    
    fig = go.Figure(data=[
        go.Bar(
            x=labels,
            y=counts,
            marker_color=colors,
            text=counts,
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis_tickangle=-45,
        height=400,
        title=dict(text="Asset Distribution by Type", font=dict(size=16)),
        showlegend=False,
        margin=dict(t=50, b=80)
    )
    
    return fig


def create_compartment_chart():
    """Create pie chart showing assets by compartment"""
    compartment_counts = get_compartment_summary()
    
    # Limit to top 10 compartments
    sorted_comps = sorted(compartment_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [c[0] or "Unknown" for c in sorted_comps]
    values = [c[1] for c in sorted_comps]
    
    # Custom color sequence matching new palette
    palette_colors = ['#5F9598', '#7DB0B3', '#4CAF7A', '#E8B84A', '#1D546D', 
                      '#8DA8B0', '#E85A5A', '#2D6680', '#A5C4C6', '#D4A84A']
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=palette_colors)
    )])
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        height=350,
        title=dict(text="Assets by Compartment", font=dict(size=16)),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.3)
    )
    
    return fig


def create_region_chart():
    """Create bar chart showing assets by region"""
    region_counts = get_region_summary()
    
    labels = list(region_counts.keys())
    values = list(region_counts.values())
    
    fig = go.Figure(data=[
        go.Bar(
            x=labels,
            y=values,
            marker_color='#5F9598',  # Muted teal accent
            text=values,
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        title=dict(text="Assets by Region", font=dict(size=16)),
        margin=dict(t=50, b=50)
    )
    
    return fig


def create_risk_gauge():
    """Create a gauge chart for overall risk score"""
    # Calculate risk score based on scan status and asset types
    # For now, use a placeholder based on unscanned percentage
    total = get_total_asset_count()
    risk_score = 45  # Placeholder - would be calculated from scan results
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score,
        delta={"reference": 50, "decreasing": {"color": "green"}, "increasing": {"color": "red"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#F3F4F4"},
            "bar": {"color": "#E8B84A"},
            "bgcolor": "#1D546D",
            "steps": [
                {"range": [0, 30], "color": "#4CAF7A"},
                {"range": [30, 70], "color": "#E8B84A"},
                {"range": [70, 100], "color": "#E85A5A"}
            ],
            "threshold": {
                "line": {"color": "#F3F4F4", "width": 4},
                "thickness": 0.75,
                "value": risk_score
            }
        },
        title={"text": "Risk Score", "font": {"size": 20, "color": "#F3F4F4"}}
    ))
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        height=280,
    )
    
    return fig


def create_recent_assets_table():
    """Create table of recent assets from database"""
    assets = get_all_assets(limit=10)
    
    if not assets:
        return html.P("No assets found in database.", className="text-muted text-center py-4")
    
    status_colors = {
        "not_scanned": "secondary",
        "scanned": "success",
        "failed": "danger",
        "pending": "warning"
    }
    
    rows = []
    for asset in assets:
        status = asset.get('scan_status', 'not_scanned')
        rows.append(html.Tr([
            html.Td(dbc.Badge(asset.get('asset_type', 'unknown').upper(), 
                             color=ASSET_TYPE_CONFIG.get(asset.get('asset_type'), {}).get('color', 'secondary'),
                             className="p-2")),
            html.Td(asset.get('name', 'Unknown')[:50] + ('...' if len(asset.get('name', '')) > 50 else '')),
            html.Td(asset.get('compartment', 'Unknown')[:30]),
            html.Td(asset.get('region', 'Unknown')),
            html.Td(dbc.Badge(status.replace('_', ' ').title(), 
                             color=status_colors.get(status, 'secondary'),
                             className="p-1")),
        ]))
    
    return dbc.Table([
        html.Thead(html.Tr([
            html.Th("Type"),
            html.Th("Name"),
            html.Th("Compartment"),
            html.Th("Region"),
            html.Th("Status"),
        ])),
        html.Tbody(rows)
    ], bordered=True, color="dark", hover=True, responsive=True, striped=True)


# Page layout
def layout():
    return dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fas fa-shield-alt me-3"),
                "LynxMap Dashboard"
            ], className="text-white mb-2"),
            html.P([
                "OCI Attack Surface Overview",
                html.Span(id="total-assets-badge", className="ms-3")
            ], className="text-muted lead"),
        ], md=8),
        dbc.Col([
            dbc.Button([
                html.I(className="fas fa-sync-alt me-2"),
                "Refresh Data"
            ], id="refresh-btn", color="primary", className="float-end")
        ], md=4, className="d-flex align-items-center justify-content-end")
    ], className="mb-4"),
    
    # Summary cards
    dbc.Row(id="asset-summary-cards", children=create_asset_summary_cards(), className="mb-4"),
    
    # Charts row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-bar me-2"),
                    "Asset Distribution"
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="asset-distribution-chart",
                        figure=create_asset_distribution_chart(),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary")
        ], lg=8, md=12),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-tachometer-alt me-2"),
                    "Overall Risk"
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="risk-gauge",
                        figure=create_risk_gauge(),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary")
        ], lg=4, md=12),
    ], className="mb-4"),
    
    # Second chart row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-sitemap me-2"),
                    "Compartment Distribution"
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="compartment-chart",
                        figure=create_compartment_chart(),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary")
        ], lg=6, md=12),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-globe me-2"),
                    "Region Distribution"
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="region-chart",
                        figure=create_region_chart(),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary")
        ], lg=6, md=12),
    ], className="mb-4"),
    
    # Recent assets
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-list me-2"),
                    "Recent Assets"
                ]),
                dbc.CardBody([
                    html.Div(id="recent-assets-table", children=create_recent_assets_table())
                ])
            ], className="bg-dark border-secondary")
        ])
    ]),
], fluid=True)


# Callbacks
@callback(
    Output("total-assets-badge", "children"),
    Input("refresh-btn", "n_clicks"),
    prevent_initial_call=False
)
def update_total_badge(_):
    """Update the total assets badge"""
    total = get_total_asset_count()
    return dbc.Badge(f"{total:,} Total Assets", color="info", className="p-2")


@callback(
    [Output("asset-summary-cards", "children"),
     Output("asset-distribution-chart", "figure"),
     Output("compartment-chart", "figure"),
     Output("region-chart", "figure"),
     Output("recent-assets-table", "children")],
    Input("refresh-btn", "n_clicks"),
    prevent_initial_call=True
)
def refresh_data(_):
    """Refresh all dashboard data"""
    return (
        create_asset_summary_cards(),
        create_asset_distribution_chart(),
        create_compartment_chart(),
        create_region_chart(),
        create_recent_assets_table()
    )
