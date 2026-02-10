"""
LynxMap - OCI Attack Surface Management Dashboard
Main application entrypoint with multi-page routing
"""

import dash
from dash import html, dcc
import dash_bootstrap_components as dbc
from dotenv import load_dotenv
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
load_dotenv()

# Initialize the Dash app with Bootstrap theme
app = dash.Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[
        dbc.themes.CYBORG,  # Dark theme for security dashboard
        dbc.icons.FONT_AWESOME
    ],
    suppress_callback_exceptions=True,
    title="LynxMap - OCI Attack Surface Manager",
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"},
        {"name": "description", "content": "OCI Attack Surface Management Dashboard"}
    ]
)

# Import sidebar component
from components.navbar import create_sidebar

# Main layout with vertical sidebar
app.layout = dbc.Container([
    dbc.Row([
        # Sidebar Column (Fixed width or percentage)
        dbc.Col(
            create_sidebar(),
            width=2,
            className="px-0 vh-100 bg-dark sidebar-col sticky-top"
        ),
        
        # Main Content Column
        dbc.Col(
            [
                # Page container
                html.Div([
                    dash.page_container
                ], className="main-content py-4 px-4"),
                
                # Global notification area
                html.Div(id="global-notifications"),
                
                # Store for shared state
                dcc.Store(id="inventory-store", storage_type="session"),
                dcc.Store(id="scan-results-store", storage_type="session"),
                
                # Interval for auto-refresh (disabled by default - 5 min interval)
                dcc.Interval(id="auto-refresh", interval=300000, disabled=True),
            ],
            width=10,
            className="px-0 bg-secondary-dark min-vh-100"
        )
    ], className="g-0 h-100") # g-0 for no gutter, h-100 for full height
], fluid=True, className="px-0 mh-100 overflow-hidden")

# Server instance for deployment
server = app.server

if __name__ == "__main__":
    # Initialize database
    from db.database import init_database, get_total_asset_count
    init_database()
    
    total_assets = get_total_asset_count()
    print(f"📊 Database contains {total_assets:,} assets")
    
    debug_mode = os.getenv("LYNXMAP_DEBUG", "true").lower() == "true"
    port = int(os.getenv("LYNXMAP_PORT", 8050))
    host = os.getenv("LYNXMAP_HOST", "127.0.0.1")
    
    print(f"🔒 Starting LynxMap on http://{host}:{port}")
    app.run(debug=debug_mode, port=port, host=host)
