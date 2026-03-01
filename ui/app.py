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
                
                # Interval for auto-refresh (2 sec interval for progress updates)
                dcc.Interval(id="auto-refresh", interval=2000, disabled=False),
            ],
            width=10,
            className="px-0 bg-secondary-dark min-vh-100"
        )
    ], className="g-0 h-100") # g-0 for no gutter, h-100 for full height
], fluid=True, className="px-0 mh-100 overflow-hidden")

# Server instance for deployment
server = app.server

# ── OCI Object download route ─────────────────────────────────────────────
from flask import request, Response
import logging

_download_logger = logging.getLogger("lynxmap.download")


@server.route("/download-object")
def download_oci_object():
    """Stream an OCI Object Storage object to the browser as a download."""
    ns = request.args.get("ns", "")
    bucket = request.args.get("bucket", "")
    obj = request.args.get("object", "")
    region = request.args.get("region", "")

    if not all([ns, bucket, obj]):
        return "Missing required parameters (ns, bucket, object)", 400

    try:
        from collectors.oci_collector import OCICollector
        collector = OCICollector()
        client = collector.clients["object_storage"]

        response = client.get_object(
            namespace_name=ns,
            bucket_name=bucket,
            object_name=obj,
        )

        # Determine content type
        content_type = (
            response.headers.get("Content-Type", "application/octet-stream")
        )

        # Derive a safe filename from the object name
        import os
        filename = os.path.basename(obj)

        def generate():
            for chunk in response.data.raw.stream(1024 * 1024):
                yield chunk

        return Response(
            generate(),
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": content_type,
            },
        )

    except Exception as e:
        _download_logger.error("Download failed for %s/%s/%s: %s", ns, bucket, obj, e)
        return f"Download failed: {e}", 500

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
