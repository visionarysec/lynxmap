"""
LynxMap - Reusable Asset Table Component
"""

import dash
from dash import html
import dash_bootstrap_components as dbc


def create_asset_table(assets, columns=None):
    """Create a reusable asset data table"""
    if columns is None:
        columns = ["Name", "Type", "Compartment", "Status", "Risk"]
    
    header = html.Thead(html.Tr([html.Th(col) for col in columns]))
    
    rows = []
    for asset in assets:
        row_cells = [html.Td(asset.get(col.lower(), "-")) for col in columns]
        rows.append(html.Tr(row_cells))
    
    body = html.Tbody(rows)
    
    return dbc.Table(
        [header, body],
        bordered=True,
        dark=True,
        hover=True,
        responsive=True,
        striped=True
    )
