"""
LynxMap - Blast Radius Analysis Page
Visualize the potential impact zone if an asset is compromised
"""

import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import numpy as np
import sys
from pathlib import Path

# Add parent directory to path for database import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from db.database import (
    search_assets_for_blast_radius,
    calculate_blast_radius,
    get_blast_radius_graph_data,
    get_asset_by_name,
    init_database
)

# Register this page
dash.register_page(__name__, path="/blast-radius", name="Blast Radius", title="LynxMap - Blast Radius Analysis")

# Initialize database
init_database()

# Asset type colors - Deep Navy Teal Palette
ASSET_COLORS = {
    "vm": "#5F9598",
    "vnic": "#7DB0B3",
    "bucket": "#E8B84A",
    "iam": "#E85A5A",
    "lb": "#4CAF7A",
}

RISK_COLORS = {
    "critical": "#E85A5A",
    "high": "#E8944A",
    "medium": "#E8B84A",
    "low": "#4CAF7A",
}


def create_network_graph(graph_data):
    """Create a network graph visualization for blast radius"""
    if not graph_data or 'error' in graph_data or not graph_data.get('nodes'):
        # Return empty figure with message
        fig = go.Figure()
        fig.add_annotation(
            text="Select an asset to visualize blast radius",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=18, color="#adb5bd")
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=600,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        return fig
    
    nodes = graph_data['nodes']
    edges = graph_data['edges']
    
    # Generate positions using circular layout
    n_nodes = len(nodes)
    
    # Source node at center
    positions = {}
    positions[nodes[0]['id']] = (0, 0)
    
    # Direct connections in inner ring
    direct_nodes = [n for n in nodes if n['group'] == 'direct']
    for i, node in enumerate(direct_nodes):
        angle = 2 * np.pi * i / max(len(direct_nodes), 1)
        radius = 1.5
        positions[node['id']] = (radius * np.cos(angle), radius * np.sin(angle))
    
    # Indirect connections in outer ring
    indirect_nodes = [n for n in nodes if n['group'] == 'indirect']
    for i, node in enumerate(indirect_nodes):
        angle = 2 * np.pi * i / max(len(indirect_nodes), 1) + 0.2  # Offset
        radius = 3
        positions[node['id']] = (radius * np.cos(angle), radius * np.sin(angle))
    
    # Create edge traces
    edge_x = []
    edge_y = []
    for edge in edges:
        if edge['source'] in positions and edge['target'] in positions:
            x0, y0 = positions[edge['source']]
            x1, y1 = positions[edge['target']]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#2D6680'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Create separate traces for each node group
    traces = [edge_trace]
    
    # Source node (center, red)
    source_nodes = [n for n in nodes if n['group'] == 'source']
    if source_nodes:
        source_x = [positions.get(n['id'], (0, 0))[0] for n in source_nodes]
        source_y = [positions.get(n['id'], (0, 0))[1] for n in source_nodes]
        source_text = [f"<b>{n['label']}</b><br>Type: {n['type'].upper()}<br>🎯 SOURCE" for n in source_nodes]
        
        traces.append(go.Scatter(
            x=source_x, y=source_y,
            mode='markers+text',
            hoverinfo='text',
            text=[n['label'][:15] for n in source_nodes],
            textposition="bottom center",
            textfont=dict(size=10, color='#F3F4F4'),
            hovertext=source_text,
            marker=dict(
                size=40,
                color='#E85A5A',
                line=dict(width=3, color='#F3F4F4'),
                symbol='circle'
            ),
            name='Source Asset'
        ))
    
    # Direct connections (1 hop)
    if direct_nodes:
        direct_x = [positions.get(n['id'], (0, 0))[0] for n in direct_nodes]
        direct_y = [positions.get(n['id'], (0, 0))[1] for n in direct_nodes]
        direct_colors = [ASSET_COLORS.get(n['type'], '#6c757d') for n in direct_nodes]
        direct_text = [f"<b>{n['label']}</b><br>Type: {n['type'].upper()}<br>1 hop (direct)" for n in direct_nodes]
        
        traces.append(go.Scatter(
            x=direct_x, y=direct_y,
            mode='markers',
            hoverinfo='text',
            hovertext=direct_text,
            marker=dict(
                size=25,
                color=direct_colors,
                line=dict(width=2, color='#F3F4F4'),
                symbol='circle'
            ),
            name='Direct (1 hop)'
        ))
    
    # Indirect connections (2+ hops)
    if indirect_nodes:
        indirect_x = [positions.get(n['id'], (0, 0))[0] for n in indirect_nodes]
        indirect_y = [positions.get(n['id'], (0, 0))[1] for n in indirect_nodes]
        indirect_colors = [ASSET_COLORS.get(n['type'], '#6c757d') for n in indirect_nodes]
        indirect_text = [f"<b>{n['label']}</b><br>Type: {n['type'].upper()}<br>2+ hops (indirect)" for n in indirect_nodes]
        
        traces.append(go.Scatter(
            x=indirect_x, y=indirect_y,
            mode='markers',
            hoverinfo='text',
            hovertext=indirect_text,
            marker=dict(
                size=18,
                color=indirect_colors,
                line=dict(width=1, color='#8DA8B0'),
                symbol='circle',
                opacity=0.7
            ),
            name='Indirect (2+ hops)'
        ))
    
    fig = go.Figure(data=traces)
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5
        ),
        height=600,
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        hovermode='closest'
    )
    
    return fig


def create_impact_summary_cards(summary):
    """Create summary cards for blast radius impact"""
    if not summary:
        return html.Div()
    
    risk_level = summary.get('risk_level', 'low')
    total = summary.get('total_impacted', 0)
    by_type = summary.get('by_type', {})
    compartments = summary.get('compartments_affected', [])
    
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-radiation fa-2x", 
                               style={"color": RISK_COLORS.get(risk_level, '#6c757d')}),
                    ], className="mb-2"),
                    html.H3(risk_level.upper(), 
                            style={"color": RISK_COLORS.get(risk_level, '#6c757d')},
                            className="mb-1"),
                    html.Small("Risk Level", className="text-muted"),
                ])
            ], className="bg-dark border-0 text-center h-100")
        ], lg=3, md=6, sm=6, className="mb-3"),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-project-diagram fa-2x text-danger"),
                    ], className="mb-2"),
                    html.H3(f"{total:,}", className="text-white mb-1"),
                    html.Small("Total Impacted", className="text-muted"),
                ])
            ], className="bg-dark border-0 text-center h-100")
        ], lg=3, md=6, sm=6, className="mb-3"),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-folder-tree fa-2x text-info"),
                    ], className="mb-2"),
                    html.H3(f"{len(compartments)}", className="text-white mb-1"),
                    html.Small("Compartments", className="text-muted"),
                ])
            ], className="bg-dark border-0 text-center h-100")
        ], lg=3, md=6, sm=6, className="mb-3"),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-cubes fa-2x text-warning"),
                    ], className="mb-2"),
                    html.H3(f"{len(by_type)}", className="text-white mb-1"),
                    html.Small("Asset Types", className="text-muted"),
                ])
            ], className="bg-dark border-0 text-center h-100")
        ], lg=3, md=6, sm=6, className="mb-3"),
    ])


# Page layout
layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fas fa-radiation me-3"),
                "Blast Radius Analysis"
            ], className="text-white mb-2"),
            html.P("Visualize the potential impact zone if an asset is compromised", 
                   className="text-muted lead"),
        ])
    ], className="mb-4"),
    
    # Asset selection
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-crosshairs me-2"),
                    "Select Target Asset"
                ]),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fas fa-search")),
                                dbc.Input(
                                    id="blast-asset-search",
                                    placeholder="Search for an asset by name...",
                                    type="text",
                                    debounce=True
                                ),
                            ]),
                            html.Div(id="blast-search-results", className="mt-2")
                        ], md=8),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fas fa-bomb me-2"),
                                "Analyze Blast Radius"
                            ], id="analyze-blast-btn", color="danger", className="w-100", disabled=True)
                        ], md=4),
                    ]),
                    html.Div(id="selected-asset-display", className="mt-3")
                ])
            ], className="bg-dark border-secondary")
        ])
    ], className="mb-4"),
    
    # Impact summary cards
    html.Div(id="blast-impact-summary"),
    
    # Main visualization
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-project-diagram me-2"),
                    "Impact Network Graph",
                    html.Small(" (hover over nodes for details)", className="text-muted ms-2")
                ]),
                dbc.CardBody([
                    dcc.Graph(
                        id="blast-network-graph",
                        figure=create_network_graph(None),
                        config={"displayModeBar": False}
                    )
                ])
            ], className="bg-dark border-secondary")
        ], lg=8, md=12),
        
        dbc.Col([
            # Legend
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-info-circle me-2"),
                    "Understanding Blast Radius"
                ]),
                dbc.CardBody([
                    html.H6("Connection Types", className="text-white mb-3"),
                    html.Div([
                        html.Div([
                            html.Span("●", style={"color": "#E85A5A", "fontSize": "24px"}),
                            html.Span(" Source Asset", className="ms-2")
                        ], className="mb-2"),
                        html.Div([
                            html.Span("●", style={"color": "#5F9598", "fontSize": "20px"}),
                            html.Span(" Direct (1 hop) - Same compartment", className="ms-2 small")
                        ], className="mb-2"),
                        html.Div([
                            html.Span("●", style={"color": "#7DB0B3", "fontSize": "16px", "opacity": 0.7}),
                            html.Span(" Indirect (2+ hops) - Same region", className="ms-2 small")
                        ], className="mb-2"),
                    ], className="mb-4"),
                    
                    html.H6("Asset Types", className="text-white mb-3"),
                    html.Div([
                        html.Div([
                            html.Span("●", style={"color": ASSET_COLORS['vm']}),
                            html.Span(" VMs", className="ms-2 small")
                        ], className="mb-1"),
                        html.Div([
                            html.Span("●", style={"color": ASSET_COLORS['vnic']}),
                            html.Span(" VNICs", className="ms-2 small")
                        ], className="mb-1"),
                        html.Div([
                            html.Span("●", style={"color": ASSET_COLORS['bucket']}),
                            html.Span(" Buckets", className="ms-2 small")
                        ], className="mb-1"),
                        html.Div([
                            html.Span("●", style={"color": ASSET_COLORS['iam']}),
                            html.Span(" IAM", className="ms-2 small")
                        ], className="mb-1"),
                        html.Div([
                            html.Span("●", style={"color": ASSET_COLORS['lb']}),
                            html.Span(" Load Balancers", className="ms-2 small")
                        ], className="mb-1"),
                    ]),
                ])
            ], className="bg-dark border-secondary mb-3"),
            
            # Impacted assets breakdown
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-list me-2"),
                    "Impact Breakdown"
                ]),
                dbc.CardBody([
                    html.Div(id="blast-breakdown", children=[
                        html.P("Select an asset to see breakdown", className="text-muted text-center py-3")
                    ])
                ])
            ], className="bg-dark border-secondary")
        ], lg=4, md=12),
    ]),
    
    # Hidden stores
    dcc.Store(id="selected-blast-asset-store"),
    dcc.Store(id="blast-radius-data-store"),
    
], fluid=True)


# Callbacks
@callback(
    Output("blast-search-results", "children"),
    Input("blast-asset-search", "value"),
    prevent_initial_call=True
)
def search_assets(query):
    """Search for assets as user types"""
    if not query or len(query) < 2:
        return html.Small("Type at least 2 characters to search...", className="text-muted")
    
    results = search_assets_for_blast_radius(query, limit=10)
    
    if not results:
        return html.Small("No assets found", className="text-muted")
    
    buttons = []
    for asset in results:
        buttons.append(
            dbc.Button(
                [
                    dbc.Badge(asset['asset_type'].upper(), 
                              color="info" if asset['asset_type'] == 'vm' else "secondary",
                              className="me-2"),
                    asset['name'][:40],
                    html.Small(f" | {asset['compartment'][:20]}...", className="text-muted")
                ],
                id={"type": "select-blast-asset", "index": asset['name']},
                color="dark",
                outline=True,
                size="sm",
                className="me-2 mb-2"
            )
        )
    
    return html.Div(buttons)


@callback(
    [Output("selected-asset-display", "children"),
     Output("selected-blast-asset-store", "data"),
     Output("analyze-blast-btn", "disabled")],
    Input({"type": "select-blast-asset", "index": dash.ALL}, "n_clicks"),
    State({"type": "select-blast-asset", "index": dash.ALL}, "id"),
    prevent_initial_call=True
)
def select_asset(n_clicks, ids):
    """Handle asset selection"""
    if not any(n_clicks):
        return html.Div(), None, True
    
    # Find which button was clicked
    ctx = dash.callback_context
    if not ctx.triggered:
        return html.Div(), None, True
    
    triggered_id = ctx.triggered[0]['prop_id']
    
    # Extract asset name from the triggered ID
    for i, btn_id in enumerate(ids):
        if n_clicks[i]:
            asset_name = btn_id['index']
            asset = get_asset_by_name(asset_name)
            
            if asset:
                display = dbc.Alert([
                    html.Strong("Selected: "),
                    dbc.Badge(asset['asset_type'].upper(), color="info", className="me-2"),
                    asset['name'],
                    html.Br(),
                    html.Small([
                        html.I(className="fas fa-folder me-1"),
                        asset['compartment'],
                        html.Span(" | ", className="mx-2"),
                        html.I(className="fas fa-globe me-1"),
                        asset['region']
                    ], className="text-muted")
                ], color="dark", className="mb-0")
                
                return display, asset, False
    
    return html.Div(), None, True


@callback(
    [Output("blast-network-graph", "figure"),
     Output("blast-impact-summary", "children"),
     Output("blast-breakdown", "children"),
     Output("blast-radius-data-store", "data")],
    Input("analyze-blast-btn", "n_clicks"),
    State("selected-blast-asset-store", "data"),
    prevent_initial_call=True
)
def analyze_blast_radius(n_clicks, asset):
    """Perform blast radius analysis and update visualizations"""
    if not asset:
        return create_network_graph(None), html.Div(), html.P("Select an asset", className="text-muted"), None
    
    # Get graph data
    graph_data = get_blast_radius_graph_data(asset)
    
    if 'error' in graph_data:
        return create_network_graph(None), html.Div(), html.P(graph_data['error'], className="text-danger"), None
    
    # Create network graph
    fig = create_network_graph(graph_data)
    
    # Create summary cards
    summary_cards = create_impact_summary_cards(graph_data['summary'])
    
    # Create breakdown
    by_type = graph_data['summary'].get('by_type', {})
    breakdown_items = []
    
    for asset_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        color = ASSET_COLORS.get(asset_type, '#6c757d')
        breakdown_items.append(
            dbc.ListGroupItem([
                dbc.Row([
                    dbc.Col([
                        html.Span("●", style={"color": color, "fontSize": "16px"}),
                        html.Span(f" {asset_type.upper()}", className="ms-2")
                    ], width=6),
                    dbc.Col([
                        dbc.Badge(f"{count}", color="light", text_color="dark")
                    ], width=6, className="text-end")
                ])
            ], className="bg-dark border-secondary py-2")
        )
    
    if not breakdown_items:
        breakdown = html.P("No impacted assets found", className="text-muted text-center")
    else:
        breakdown = html.Div([
            dbc.ListGroup(breakdown_items, flush=True),
            html.Hr(className="border-secondary"),
            html.Div([
                html.Strong("Direct connections: ", className="text-muted"),
                html.Span(f"{graph_data['direct_count']}", className="text-info")
            ], className="mb-1"),
            html.Div([
                html.Strong("Indirect connections: ", className="text-muted"),
                html.Span(f"{graph_data['indirect_count']}", className="text-warning")
            ], className="mb-1"),
            html.Div([
                html.Strong("IAM policies: ", className="text-muted"),
                html.Span(f"{graph_data['iam_count']}", className="text-danger")
            ]),
        ])
    
    return fig, summary_cards, breakdown, graph_data
