"""
LynxMap - Exposure Page (Attack Surface Explorer)
Sunburst → Asset Type Buttons → Asset Table (OCI)
Based on lynxmap_ui_sunburst_buttons.py approach
"""

import dash
from dash import html, dcc, callback, Input, Output, State, dash_table, ALL, ctx
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import sys
from pathlib import Path
from collections import Counter

# Add parent directory to path for database import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import (
    get_compartments_for_sunburst,
    get_asset_counts_by_compartment,
    get_assets_by_compartment_and_type,
    get_asset_summary,
    init_database
)

# Register this page
dash.register_page(__name__, path="/exposure", name="Exposure", title="LynxMap - Attack Surface")

# Initialize database
init_database()

# Asset type button colors - Deep Navy Teal Palette
ASSET_COLORS = {
    "vm": {"bg": "#5F9598", "label": "Virtual Machines", "icon": "fa-server"},
    "vnic": {"bg": "#7DB0B3", "label": "VNICs", "icon": "fa-network-wired"},
    "bucket": {"bg": "#E8B84A", "label": "Storage Buckets", "icon": "fa-bucket"},
    "iam": {"bg": "#E85A5A", "label": "IAM Policies", "icon": "fa-users-cog"},
    "lb": {"bg": "#4CAF7A", "label": "Load Balancers", "icon": "fa-balance-scale"},
}


def create_compartment_sunburst():
    """Create sunburst chart from compartment hierarchy"""
    data = get_compartments_for_sunburst()
    
    if not data['ids']:
        # If no compartments loaded, return empty figure
        fig = go.Figure()
        fig.add_annotation(
            text="No compartment data. Please import compartments.",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color="white")
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            height=700
        )
        return fig
    
    fig = px.sunburst(
        ids=data['ids'],
        names=data['labels'],
        parents=data['parents'],
        values=data['values'],
        maxdepth=4,
        title="OCI Compartment Hierarchy"
    )
    
    # Pastel color sequence for sunburst
    pastel_colors = [
        '#A5C4C6', # Pastel Teal
        '#B8D8E0', # Pastel Blue
        '#C1E1C1', # Pastel Green
        '#EEDC9A', # Pastel Gold
        '#F2BBA0', # Pastel Coral
        '#D4C4FB', # Pastel Lavender
        '#F3F4F4', # Off-White
        '#8DA8B0'  # Muted Blue-Grey
    ]
    
    fig.update_traces(
        marker=dict(colors=pastel_colors),
        hovertemplate="<b>%{label}</b><br>Assets: %{value}<extra></extra>",
        insidetextorientation='radial',
        leaf=dict(opacity=0.9)
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=50, l=10, r=10, b=10),
        height=700,
        title=dict(
            text="OCI Compartment Hierarchy",
            font=dict(size=18, color="#F3F4F4"),
            x=0.5
        )
    )
    
    return fig


def create_stats_cards():
    """Create asset statistics cards"""
    asset_counts = get_asset_summary()
    total = sum(asset_counts.values())
    
    cards = []
    cards.append(
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-cubes fa-2x", style={"color": "#F3F4F4"}),
                    ], className="mb-2"),
                    html.H3(f"{total:,}", className="mb-1", style={"color": "#F3F4F4"}),
                    html.Small("Total Assets", className="text-muted"),
                ])
            ], className="bg-dark border-secondary text-center h-100 asset-card")
        ], lg=2, md=4, sm=6, className="mb-3")
    )
    
    for asset_type, count in list(asset_counts.items())[:4]:
        config = ASSET_COLORS.get(asset_type, {"bg": "#6c757d", "icon": "fa-cube", "label": asset_type.upper()})
        cards.append(
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className=f"fas {config['icon']} fa-2x", 
                                   style={"color": config['bg']}),
                        ], className="mb-2"),
                        html.H3(f"{count:,}", className="text-white mb-1"),
                        html.Small(config['label'], className="text-muted"),
                    ])
                ], className="bg-dark border-0 text-center")
            ], lg=2, md=4, sm=6, className="mb-3")
        )
    
    return dbc.Row(cards, className="mb-4")


# Page layout
layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fas fa-crosshairs me-3"),
                "Attack Surface Explorer"
            ], className="text-white mb-2"),
            html.P("Click a compartment to explore assets, then select an asset type", 
                   className="text-muted lead"),
        ])
    ], className="mb-4"),
    
    # Stats cards
    create_stats_cards(),
    
    # Main content
    dbc.Row([
        # Sunburst chart column
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-sitemap me-2"),
                    "Compartment Hierarchy",
                    html.Small(" (click to explore)", className="text-muted ms-2")
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="compartment-sunburst",
                        figure=create_compartment_sunburst(),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary h-100")
        ], lg=7, md=12),
        
        # Asset explorer column
        dbc.Col([
            # Selected compartment info
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-folder-open me-2"),
                    "Selected Compartment"
                ]),
                dbc.CardBody([
                    html.Div(id="selected-compartment-info", children=[
                        html.P("Click a compartment in the sunburst chart to view its assets.", 
                               className="text-muted text-center my-3"),
                        html.Div([
                            html.I(className="fas fa-mouse-pointer fa-3x text-secondary"),
                        ], className="text-center")
                    ])
                ])
            ], className="bg-dark border-secondary mb-3"),
            
            # Asset type buttons
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-cubes me-2"),
                    "Asset Types"
                ]),
                dbc.CardBody([
                    html.Div(id="asset-type-buttons", children=[
                        html.P("Select a compartment first", className="text-muted text-center py-3")
                    ])
                ])
            ], className="bg-dark border-secondary mb-3"),
            
            # Asset table (Moved here)
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-table me-2"),
                    html.Span("Assets", id="asset-table-title"),
                ]),
                dbc.CardBody([
                    html.Div(id="asset-table-container", children=[
                        html.P("Select a compartment and asset type to view assets.", 
                               className="text-muted text-center py-4")
                    ])
                ])
            ], className="bg-dark border-secondary")
            
        ], lg=5, md=12),
    ], className="mb-4"),
    
    # Hidden stores for state
    dcc.Store(id="selected-compartment-store"),
    dcc.Store(id="selected-asset-type-store"),
    
], fluid=True)


# Callbacks
@callback(
    [Output("selected-compartment-info", "children"),
     Output("asset-type-buttons", "children"),
     Output("selected-compartment-store", "data")],
    Input("compartment-sunburst", "clickData"),
    prevent_initial_call=True
)
def handle_compartment_click(click_data):
    """Handle compartment selection from sunburst"""
    if not click_data:
        return (
            html.P("Click a compartment to view assets.", className="text-muted"),
            html.P("Select a compartment first", className="text-muted text-center py-3"),
            None
        )
    
    # Get the clicked compartment label
    comp_label = click_data["points"][0].get("label", "Unknown")
    
    # Get asset counts for this compartment
    asset_counts = get_asset_counts_by_compartment(comp_label)
    
    # Build compartment info
    total_assets = sum(asset_counts.values())
    comp_info = html.Div([
        html.H5(comp_label, className="text-white mb-2"),
        html.Div([
            dbc.Badge(f"{total_assets:,} assets", color="info", className="me-2 p-2"),
            dbc.Badge(f"{len(asset_counts)} types", color="secondary", className="p-2"),
        ], className="mb-2"),
    ])
    
    # Build asset type buttons
    if not asset_counts:
        buttons = html.P("No assets in this compartment", className="text-muted text-center py-3")
    else:
        button_elements = []
        for asset_type, count in asset_counts.items():
            config = ASSET_COLORS.get(asset_type, {"bg": "#6c757d", "label": asset_type.upper(), "icon": "fa-cube"})
            button_elements.append(
                dbc.Button(
                    [
                        html.I(className=f"fas {config['icon']} me-2"),
                        f"{count} {config['label']}"
                    ],
                    id={"type": "asset-type-btn", "index": asset_type},
                    n_clicks=0,
                    color="dark",
                    outline=True,
                    className="m-1",
                    style={
                        "borderColor": config['bg'],
                        "color": config['bg']
                    }
                )
            )
        buttons = html.Div(button_elements, className="d-flex flex-wrap")
    
    return comp_info, buttons, comp_label


@callback(
    [Output("asset-table-container", "children"),
     Output("asset-table-title", "children"),
     Output("selected-asset-type-store", "data")],
    Input({"type": "asset-type-btn", "index": ALL}, "n_clicks"),
    State("selected-compartment-store", "data"),
    State({"type": "asset-type-btn", "index": ALL}, "id"),
    prevent_initial_call=True
)
def handle_asset_type_click(n_clicks, comp_label, button_ids):
    """Handle asset type button click - show assets in table"""
    if not comp_label or not any(n_clicks):
        return (
            html.P("Select a compartment and asset type.", className="text-muted text-center py-4"),
            "Assets",
            None
        )
    
    # Find which button was clicked
    triggered = ctx.triggered_id
    if not triggered or not isinstance(triggered, dict):
        return (
            html.P("Select an asset type.", className="text-muted text-center py-4"),
            "Assets",
            None
        )
    
    clicked_type = triggered.get("index")
    if not clicked_type:
        return (
            html.P("Select an asset type.", className="text-muted text-center py-4"),
            "Assets",
            None
        )
    
    # Get assets for this compartment and type
    assets = get_assets_by_compartment_and_type(comp_label, clicked_type)
    
    if not assets:
        return (
            html.P(f"No {clicked_type.upper()} assets found in {comp_label}.", className="text-muted text-center py-4"),
            f"Assets - {clicked_type.upper()} in {comp_label}",
            clicked_type
        )
    
    # Build DataTable
    config = ASSET_COLORS.get(clicked_type, {"label": clicked_type.upper()})
    
    table = dash_table.DataTable(
        id="asset-data-table",
        columns=[
            {"name": "Asset Name", "id": "name"},
            {"name": "Asset Type", "id": "asset_type"},
            {"name": "Asset ID", "id": "asset_id"},
            {"name": "Region", "id": "region"},
            {"name": "Scan Status", "id": "scan_status"},
        ],
        data=[
            {
                "name": a.get("name", "")[:60],
                "asset_type": a.get("asset_type", "").upper(),
                "asset_id": a.get("asset_id", "")[:50] + "..." if len(a.get("asset_id", "")) > 50 else a.get("asset_id", ""),
                "region": a.get("region", ""),
                "scan_status": a.get("scan_status", "not_scanned").replace("_", " ").title(),
            }
            for a in assets
        ],
        page_size=15,
        filter_action="native",
        sort_action="native",
        style_table={"overflowX": "auto"},
        style_cell={
            "textAlign": "left",
            "padding": "10px",
            "fontSize": "13px",
            "whiteSpace": "normal",
            "maxWidth": "300px",
            "backgroundColor": "#1D546D",
            "color": "#F3F4F4",
            "border": "1px solid #2D6680"
        },
        style_header={
            "backgroundColor": "#061E29",
            "fontWeight": "bold",
            "color": "#F3F4F4",
            "border": "1px solid #2D6680"
        },
        style_filter={
            "backgroundColor": "#061E29",
            "color": "#F3F4F4"
        },
        style_data_conditional=[
            {
                "if": {"row_index": "odd"},
                "backgroundColor": "#164258"
            },
            {
                "if": {"state": "selected"},
                "backgroundColor": "#5F9598",
                "border": "1px solid #5F9598"
            }
        ]
    )
    
    title = f"Assets - {len(assets)} {config['label']} in {comp_label}"
    
    return table, title, clicked_type
