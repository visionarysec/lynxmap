"""
LynxMap - Playbooks Page (Security Scanning Interface)
Interface for running CIS benchmarks, viewing scan results,
and running the Secret Scanner against OCI Object Storage buckets.
"""

import dash
from dash import html, dcc, callback, Input, Output, State, no_update, ctx
import dash_bootstrap_components as dbc
from datetime import datetime
from urllib.parse import quote as urlquote

# Import the secret scanner
from playbooks.secret_scanner import SecretScanner, run_secret_scan
from playbooks.cis_benchmark import CISBenchmarkRunner, run_cis_benchmark
from collectors.oci_collector import OCICollector
import logging
import threading

logger = logging.getLogger(__name__)

# Global state for background secret scan
_bg_scan_state = {
    "running": False,
    "report": None,
    "error": None,
    "progress": "",           # latest progress message
    "compartment_ids": None,  # list of OCIDs or None (all)
}

# Global state for background CIS benchmark scan
_bg_cis_state = {
    "running": False,
    "report": None,
    "error": None,
    "progress": "",
}

# Register this page
dash.register_page(__name__, path="/playbooks", name="Playbooks", title="LynxMap - Security Playbooks")


def get_available_playbooks():
    """Get list of available security playbooks"""
    return [
        {
            "id": "cis_oci_v1",
            "name": "CIS OCI Benchmark v1.2",
            "description": "Center for Internet Security - Oracle Cloud Infrastructure Benchmark",
            "checks": 87,
            "categories": ["IAM", "Networking", "Storage", "Compute", "Database"],
            "severity": "all",
            "last_run": "2024-01-15 14:30:00",
            "status": "passed"
        },
        {
            "id": "public_exposure",
            "name": "Public Exposure Scanner",
            "description": "Identifies resources with public internet exposure",
            "checks": 24,
            "categories": ["Networking", "Storage", "Compute"],
            "severity": "high",
            "last_run": "2024-01-16 09:15:00",
            "status": "failed"
        },
        {
            "id": "secret_scanner",
            "name": "Secret Scanner",
            "description": "Scans all OCI Object Storage buckets for sensitive files such as credentials, private keys, config files, and database dumps — with no time restrictions.",
            "checks": "All Objects",
            "categories": ["Storage", "Secrets"],
            "severity": "critical",
            "last_run": None,
            "status": "never_run"
        },
        {
            "id": "iam_audit",
            "name": "IAM Security Audit",
            "description": "Reviews IAM policies, users, and access patterns",
            "checks": 42,
            "categories": ["IAM"],
            "severity": "critical",
            "last_run": None,
            "status": "never_run"
        },
        {
            "id": "encryption_check",
            "name": "Encryption Compliance",
            "description": "Validates encryption at rest and in transit configurations",
            "checks": 31,
            "categories": ["Storage", "Database", "Networking"],
            "severity": "high",
            "last_run": "2024-01-14 11:00:00",
            "status": "warning"
        },
        {
            "id": "network_segmentation",
            "name": "Network Segmentation Review",
            "description": "Analyzes VCN architecture and security list configurations",
            "checks": 28,
            "categories": ["Networking"],
            "severity": "medium",
            "last_run": "2024-01-13 16:45:00",
            "status": "passed"
        }
    ]


def create_playbook_card(playbook):
    """Create a card for a single playbook"""
    status_badges = {
        "passed": dbc.Badge("Passed", color="success", className="ms-2"),
        "failed": dbc.Badge("Failed", color="danger", className="ms-2"),
        "warning": dbc.Badge("Warnings", color="warning", className="ms-2"),
        "running": dbc.Badge("Running...", color="info", className="ms-2"),
        "never_run": dbc.Badge("Never Run", color="secondary", className="ms-2"),
    }
    
    severity_colors = {
        "critical": "danger",
        "high": "warning",
        "medium": "info",
        "low": "success",
        "all": "primary"
    }
    
    category_badges = [
        dbc.Badge(cat, color="dark", className="me-1", style={"fontSize": "0.7rem"})
        for cat in playbook["categories"][:3]
    ]
    
    if len(playbook["categories"]) > 3:
        category_badges.append(
            dbc.Badge(f"+{len(playbook['categories']) - 3}", color="secondary", className="me-1")
        )
    
    return dbc.Card([
        dbc.CardHeader([
            html.Div([
                html.H5([
                    playbook["name"],
                    status_badges.get(playbook["status"], "")
                ], className="mb-0"),
            ], className="d-flex justify-content-between align-items-center")
        ], className="bg-dark"),
        dbc.CardBody([
            html.P(playbook["description"], className="text-muted mb-3"),
            html.Div([
                html.Span([
                    html.I(className="fas fa-tasks me-1"),
                    f"{playbook['checks']} checks"
                ], className="me-3 text-muted"),
                html.Span([
                    html.I(className="fas fa-shield-alt me-1"),
                    dbc.Badge(playbook["severity"].upper(), color=severity_colors[playbook["severity"]])
                ], className="me-3"),
            ], className="mb-3"),
            html.Div(category_badges, className="mb-3"),
            html.Div([
                html.Small([
                    html.I(className="fas fa-clock me-1"),
                    f"Last run: {playbook['last_run'] or 'Never'}"
                ], className="text-muted")
            ])
        ]),
        dbc.CardFooter([
            dbc.ButtonGroup([
                dbc.Button([
                    html.I(className="fas fa-play me-1"),
                    "Run"
                ], id={"type": "run-playbook", "index": playbook["id"]}, 
                   color="success", size="sm", outline=True),
                dbc.Button([
                    html.I(className="fas fa-eye me-1"),
                    "View Results"
                ], id={"type": "view-results", "index": playbook["id"]}, 
                   color="info", size="sm", outline=True),
                dbc.Button([
                    html.I(className="fas fa-cog me-1"),
                    "Configure"
                ], id={"type": "config-playbook", "index": playbook["id"]}, 
                   color="secondary", size="sm", outline=True),
            ], size="sm")
        ], className="bg-dark border-top border-secondary")
    ], className="bg-dark border-secondary mb-3")


def create_scan_results_panel():
    """Create panel showing scan results"""
    # Mock scan results
    results = [
        {"check": "1.1 - Ensure MFA is enabled for all users", "status": "PASS", "resource_count": 156},
        {"check": "1.2 - Ensure API keys rotate within 90 days", "status": "FAIL", "resource_count": 12},
        {"check": "2.1 - Ensure default security list restricts all traffic", "status": "PASS", "resource_count": 24},
        {"check": "2.2 - Ensure no security lists allow 0.0.0.0/0", "status": "FAIL", "resource_count": 3},
        {"check": "3.1 - Ensure Object Storage buckets have versioning enabled", "status": "WARN", "resource_count": 28},
        {"check": "4.1 - Ensure audit logging is enabled", "status": "PASS", "resource_count": 1},
    ]
    
    status_icons = {
        "PASS": html.I(className="fas fa-check-circle text-success"),
        "FAIL": html.I(className="fas fa-times-circle text-danger"),
        "WARN": html.I(className="fas fa-exclamation-circle text-warning"),
    }
    
    rows = []
    for result in results:
        rows.append(html.Tr([
            html.Td(status_icons[result["status"]]),
            html.Td(result["check"]),
            html.Td(result["resource_count"]),
            html.Td(
                dbc.Button([
                    html.I(className="fas fa-external-link-alt")
                ], size="sm", color="link")
            )
        ]))
    
    return dbc.Table([
        html.Thead(html.Tr([
            html.Th("Status", style={"width": "60px"}),
            html.Th("Check"),
            html.Th("Resources", style={"width": "100px"}),
            html.Th("Details", style={"width": "80px"})
        ])),
        html.Tbody(rows)
    ], bordered=True, color="dark", hover=True, responsive=True, size="sm")


def create_scan_summary():
    """Create summary statistics for scans"""
    stats = [
        {"label": "Total Checks", "value": 87, "color": "primary"},
        {"label": "Passed", "value": 72, "color": "success"},
        {"label": "Failed", "value": 8, "color": "danger"},
        {"label": "Warnings", "value": 7, "color": "warning"},
    ]
    
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(stat["value"], className=f"text-{stat['color']} mb-0"),
                    html.Small(stat["label"], className="text-muted")
                ], className="text-center py-2")
            ], className="bg-dark border-0")
        ], md=3)
        for stat in stats
    ], className="mb-4")


def _format_file_size(size_bytes):
    """Convert bytes to a human-readable string."""
    if size_bytes is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def _get_compartment_options():
    """Load compartment options from the database for the picker."""
    try:
        from db.database import get_connection
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT compartment_id, name FROM compartments ORDER BY name"
            )
            return [
                {"label": row["name"], "value": row["compartment_id"]}
                for row in cursor.fetchall()
            ]
    except Exception:
        return []


def create_secret_scanner_tab():
    """Create the Secret Scanner tab content with compartment picker and results area."""
    compartment_options = _get_compartment_options()

    return html.Div([
        # Header row
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.I(className="fas fa-user-secret me-2",
                           style={"fontSize": "1.4rem"}),
                    html.H4("Secret Scanner", className="d-inline mb-0 text-white"),
                ], className="d-flex align-items-center"),
                html.P(
                    "Scans OCI Object Storage buckets for secrets using "
                    "filename-pattern matching. Select specific compartments "
                    "below or leave empty to scan all.",
                    className="text-muted mt-2 mb-0",
                ),
            ], md=8),
            dbc.Col([
                dbc.Button([
                    html.I(className="fas fa-search me-2", id="secret-scan-icon"),
                    "Run Secret Scan"
                ], id="run-secret-scan-btn", color="danger", size="lg",
                   className="float-end"),
            ], md=4, className="d-flex align-items-center justify-content-end"),
        ], className="mb-3"),

        # Compartment picker
        dbc.Row([
            dbc.Col([
                dbc.Label(
                    [html.I(className="fas fa-sitemap me-2"), "Compartments"],
                    className="text-muted mb-1",
                    style={"fontSize": "0.85rem"},
                ),
                dcc.Dropdown(
                    id="secret-scan-compartment-picker",
                    options=compartment_options,
                    value=[],
                    multi=True,
                    placeholder="All compartments (leave empty to scan all)",
                    style={
                        "backgroundColor": "#2b3035",
                        "color": "#fff",
                    },
                    className="dash-dark-dropdown",
                ),
            ], md=12),
        ], className="mb-3"),

        # Live progress area
        html.Div(id="secret-scan-progress", className="mb-3"),

        # Summary cards (populated by callback)
        html.Div(id="secret-scan-summary"),

        # Findings table (populated by callback)
        html.Div(id="secret-scan-results", children=[
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-info-circle text-muted me-2",
                               style={"fontSize": "2rem"}),
                        html.Span(
                            'Select compartments (or leave empty for all), '
                            'then click "Run Secret Scan".',
                            className="text-muted",
                        ),
                    ], className="text-center py-5 d-flex align-items-center justify-content-center"),
                ])
            ], className="bg-dark border-secondary")
        ]),

        # Polling interval (disabled by default, enabled during scan)
        dcc.Interval(id="secret-scan-poll", interval=2000, disabled=True),
        # Store to trigger result rendering
        dcc.Store(id="secret-scan-report-store", data=None),
    ], className="mt-3")


def _create_cis_benchmark_tab():
    """Build the CIS Benchmark tab layout."""
    return html.Div([
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fas fa-shield-alt me-2",
                                   style={"fontSize": "1.6rem", "color": "#00d4ff"}),
                            html.Span("CIS OCI Foundations Benchmark v2.0",
                                      style={"fontSize": "1.2rem", "fontWeight": "600"}),
                        ], className="d-flex align-items-center mb-3"),
                        html.P(
                            "Runs 19 automated security checks across IAM, Networking, "
                            "Storage, Compute, and Logging against your live OCI tenancy.",
                            className="text-muted mb-3",
                        ),
                        dbc.Row([
                            dbc.Col([
                                dbc.Badge("7 IAM", color="primary", className="me-1"),
                                dbc.Badge("4 Networking", color="info", className="me-1"),
                                dbc.Badge("3 Storage", color="warning", className="me-1"),
                                dbc.Badge("3 Compute", color="success", className="me-1"),
                                dbc.Badge("2 Logging", color="secondary"),
                            ]),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fas fa-play me-2"),
                                    "Run CIS Benchmark",
                                ], id="cis-run-btn", color="primary",
                                   className="float-end"),
                            ], className="text-end"),
                        ]),
                    ])
                ], className="bg-dark border-secondary mb-3"),
            ])
        ]),

        # Progress bar
        html.Div(id="cis-progress-area", children=[], className="mb-3"),

        # Poll timer (disabled by default)
        dcc.Interval(
            id="cis-poll-interval",
            interval=1500,
            disabled=True,
        ),

        # Store for completed report
        dcc.Store(id="cis-report-store"),

        # Results placeholder
        html.Div(id="cis-results-area", children=[]),
    ], className="mt-3")


# ─── Page layout ──────────────────────────────────────────────────────────────────
layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fas fa-book me-3"),
                "Security Playbooks"
            ], className="text-white mb-2"),
            html.P("Configure and run security scans against your OCI infrastructure", 
                   className="text-muted lead"),
        ], md=8),
        dbc.Col([
            dbc.Button([
                html.I(className="fas fa-plus me-2"),
                "Create Playbook"
            ], id="create-playbook-btn", color="primary", className="float-end")
        ], md=4, className="d-flex align-items-center justify-content-end")
    ], className="mb-4"),
    
    # Tabs for different views
    dbc.Tabs([
        # Playbooks tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    create_playbook_card(playbook)
                    for playbook in get_available_playbooks()
                ], md=8),
                
                dbc.Col([
                    # Quick actions panel
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-bolt me-2"),
                            "Quick Actions"
                        ]),
                        dbc.CardBody([
                            dbc.Button([
                                html.I(className="fas fa-play-circle me-2"),
                                "Run All Playbooks"
                            ], color="success", className="w-100 mb-2", id="run-all-btn"),
                            dbc.Button([
                                html.I(className="fas fa-file-export me-2"),
                                "Export Results"
                            ], color="info", className="w-100 mb-2", outline=True),
                            dbc.Button([
                                html.I(className="fas fa-calendar-alt me-2"),
                                "Schedule Scans"
                            ], color="secondary", className="w-100", outline=True),
                        ])
                    ], className="bg-dark border-secondary mb-3"),
                    
                    # Recent activity
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-history me-2"),
                            "Recent Activity"
                        ]),
                        dbc.CardBody([
                            dbc.ListGroup([
                                dbc.ListGroupItem([
                                    html.Div([
                                        html.I(className="fas fa-check text-success me-2"),
                                        html.Strong("CIS OCI Benchmark"),
                                    ]),
                                    html.Small("Completed 2 hours ago", className="text-muted")
                                ], className="bg-dark border-secondary"),
                                dbc.ListGroupItem([
                                    html.Div([
                                        html.I(className="fas fa-times text-danger me-2"),
                                        html.Strong("Public Exposure Scanner"),
                                    ]),
                                    html.Small("3 issues found yesterday", className="text-muted")
                                ], className="bg-dark border-secondary"),
                                dbc.ListGroupItem([
                                    html.Div([
                                        html.I(className="fas fa-exclamation text-warning me-2"),
                                        html.Strong("Encryption Compliance"),
                                    ]),
                                    html.Small("Warnings found 3 days ago", className="text-muted")
                                ], className="bg-dark border-secondary"),
                            ], flush=True)
                        ])
                    ], className="bg-dark border-secondary")
                ], md=4)
            ], className="mt-3")
        ], label="Playbooks", tab_id="playbooks-tab"),
        
        # Results tab
        dbc.Tab([
            html.Div([
                # Summary stats
                create_scan_summary(),
                
                # Results table
                dbc.Card([
                    dbc.CardHeader([
                        dbc.Row([
                            dbc.Col([
                                html.I(className="fas fa-list-check me-2"),
                                "CIS OCI Benchmark v1.2 - Latest Results"
                            ]),
                            dbc.Col([
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fas fa-search")),
                                    dbc.Input(placeholder="Filter checks...", id="search-checks", size="sm")
                                ], size="sm", className="w-auto float-end")
                            ], className="text-end")
                        ])
                    ]),
                    dbc.CardBody([
                        create_scan_results_panel()
                    ])
                ], className="bg-dark border-secondary")
            ], className="mt-3")
        ], label="Results", tab_id="results-tab"),

        # ── Secret Scanner tab ──────────────────────────────────────────────
        dbc.Tab(
            create_secret_scanner_tab(),
            label="Secret Scanner",
            tab_id="secret-scanner-tab",
        ),
        
        # ── CIS Benchmark tab ────────────────────────────────────────────────
        dbc.Tab(
            _create_cis_benchmark_tab(),
            label="CIS Benchmark",
            tab_id="cis-benchmark-tab",
        ),

        # Custom playbook tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-code me-2"),
                            "Playbook Editor"
                        ]),
                        dbc.CardBody([
                            dbc.Textarea(
                                id="playbook-editor",
                                placeholder="""# Custom Playbook Definition
name: my_custom_playbook
description: Custom security checks

checks:
  - id: custom_001
    name: Check for public buckets
    service: object_storage
    condition: bucket.public_access_type == 'NoPublicAccess'
    severity: critical
    
  - id: custom_002
    name: Verify encryption at rest
    service: object_storage
    condition: bucket.kms_key_id != null
    severity: high
""",
                                className="font-monospace bg-dark text-white",
                                style={"height": "400px"},
                            ),
                            dbc.ButtonGroup([
                                dbc.Button([
                                    html.I(className="fas fa-check me-2"),
                                    "Validate"
                                ], color="info", className="mt-3"),
                                dbc.Button([
                                    html.I(className="fas fa-save me-2"),
                                    "Save Playbook"
                                ], color="success", className="mt-3"),
                            ])
                        ])
                    ], className="bg-dark border-secondary")
                ], md=8),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fas fa-info-circle me-2"),
                            "Playbook Syntax"
                        ]),
                        dbc.CardBody([
                            html.H6("Available Services:", className="text-white"),
                            dbc.ListGroup([
                                dbc.ListGroupItem("compute", className="bg-dark border-secondary py-1"),
                                dbc.ListGroupItem("networking", className="bg-dark border-secondary py-1"),
                                dbc.ListGroupItem("object_storage", className="bg-dark border-secondary py-1"),
                                dbc.ListGroupItem("identity", className="bg-dark border-secondary py-1"),
                                dbc.ListGroupItem("database", className="bg-dark border-secondary py-1"),
                            ], flush=True, className="mb-3"),
                            html.H6("Severity Levels:", className="text-white mt-3"),
                            html.Div([
                                dbc.Badge("critical", color="danger", className="me-1"),
                                dbc.Badge("high", color="warning", className="me-1"),
                                dbc.Badge("medium", color="info", className="me-1"),
                                dbc.Badge("low", color="success"),
                            ])
                        ])
                    ], className="bg-dark border-secondary")
                ], md=4)
            ], className="mt-3")
        ], label="Create Custom", tab_id="custom-tab"),
    ], id="playbook-tabs", active_tab="playbooks-tab"),
    
    # Progress modal for running scans
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("Running Security Scan")),
        dbc.ModalBody([
            dbc.Progress(id="scan-progress", value=0, striped=True, animated=True, className="mb-3"),
            html.Div(id="scan-status", children="Initializing scan...")
        ]),
        dbc.ModalFooter(
            dbc.Button("Cancel", id="cancel-scan-btn", color="secondary")
        )
    ], id="scan-modal", is_open=False, backdrop="static")
], fluid=True)


# ─── Callbacks ────────────────────────────────────────────────────────────────

@callback(
    Output("scan-modal", "is_open"),
    Input("run-all-btn", "n_clicks"),
    Input("cancel-scan-btn", "n_clicks"),
    State("scan-modal", "is_open"),
    prevent_initial_call=True
)
def toggle_scan_modal(run_clicks, cancel_clicks, is_open):
    """Toggle the scan progress modal"""
    return not is_open


def _bg_scan_worker():
    """Background worker that runs the secret scan."""
    try:
        collector = OCICollector()
        if not collector.config:
            logger.info("OCI not configured — falling back to mock data")
            collector = None
    except Exception as e:
        logger.warning("Could not create OCI collector: %s — using mock data", e)
        collector = None

    def _on_progress(msg):
        _bg_scan_state["progress"] = msg

    comp_ids = _bg_scan_state.get("compartment_ids") or None

    try:
        report = run_secret_scan(
            collector=collector,
            compartment_ids=comp_ids,
            progress_callback=_on_progress,
        )
        _bg_scan_state["report"] = report
        _bg_scan_state["error"] = None
    except Exception as e:
        logger.error("Background secret scan failed: %s", e)
        _bg_scan_state["report"] = None
        _bg_scan_state["error"] = str(e)
    finally:
        _bg_scan_state["running"] = False


# ── Callback 1: Start scan (button click → launch thread + show spinner) ──
@callback(
    Output("run-secret-scan-btn", "disabled", allow_duplicate=True),
    Output("run-secret-scan-btn", "children", allow_duplicate=True),
    Output("secret-scan-poll", "disabled"),
    Output("secret-scan-summary", "children", allow_duplicate=True),
    Output("secret-scan-results", "children", allow_duplicate=True),
    Output("secret-scan-progress", "children", allow_duplicate=True),
    Input("run-secret-scan-btn", "n_clicks"),
    State("secret-scan-compartment-picker", "value"),
    prevent_initial_call=True,
)
def start_secret_scan(n_clicks, selected_compartments):
    """Launch the secret scan in a background thread."""
    if not n_clicks or _bg_scan_state["running"]:
        return (no_update,) * 6

    # Reset state and store selected compartments
    _bg_scan_state["running"] = True
    _bg_scan_state["report"] = None
    _bg_scan_state["error"] = None
    _bg_scan_state["progress"] = "Initializing…"
    _bg_scan_state["compartment_ids"] = (
        selected_compartments if selected_compartments else None
    )

    t = threading.Thread(target=_bg_scan_worker, daemon=True)
    t.start()

    # Show progress UI
    btn_children = [
        dbc.Spinner(size="sm", spinner_class_name="me-2"),
        "Scanning…",
    ]

    scope = (
        f"{len(selected_compartments)} selected compartment(s)"
        if selected_compartments
        else "all active compartments"
    )

    progress_bar = html.Div([
        dbc.Card([
            dbc.CardBody([
                html.Div([
                    dbc.Spinner(color="danger", type="grow", size="sm",
                                spinner_class_name="me-3"),
                    html.Span(
                        f"Scanning {scope} — please wait…",
                        className="text-warning",
                    ),
                ], className="d-flex align-items-center"),
                html.Div(
                    "Initializing…",
                    id="secret-scan-progress-text",
                    className="text-muted mt-2",
                    style={"fontSize": "0.85rem", "fontFamily": "monospace"},
                ),
            ])
        ], className="bg-dark border-warning"),
    ])

    # Enable polling, disable button, show spinner
    return True, btn_children, False, html.Div(), html.Div(), progress_bar


# ── Callback 2: Poll for results + update progress ───────────────────────
@callback(
    Output("secret-scan-report-store", "data"),
    Output("secret-scan-poll", "disabled", allow_duplicate=True),
    Output("secret-scan-progress", "children", allow_duplicate=True),
    Input("secret-scan-poll", "n_intervals"),
    prevent_initial_call=True,
)
def poll_secret_scan(n_intervals):
    """Check if the background scan has completed and relay progress."""
    progress_msg = _bg_scan_state.get("progress", "")

    progress_ui = html.Div([
        dbc.Card([
            dbc.CardBody([
                html.Div([
                    dbc.Spinner(color="danger", type="grow", size="sm",
                                spinner_class_name="me-3"),
                    html.Span("Scanning…", className="text-warning"),
                ], className="d-flex align-items-center"),
                html.Div(
                    progress_msg or "Working…",
                    className="text-muted mt-2",
                    style={"fontSize": "0.85rem", "fontFamily": "monospace"},
                ),
            ])
        ], className="bg-dark border-warning"),
    ])

    if _bg_scan_state["running"]:
        # Still running — update progress, keep polling
        return no_update, False, progress_ui

    # Done — push results to store and stop polling
    if _bg_scan_state["error"]:
        return {"error": _bg_scan_state["error"]}, True, html.Div()

    if _bg_scan_state["report"]:
        return _bg_scan_state["report"], True, html.Div()

    return no_update, True, html.Div()


# ── Callback 3: Render results from store ─────────────────────────────────
@callback(
    Output("secret-scan-summary", "children"),
    Output("secret-scan-results", "children"),
    Output("run-secret-scan-btn", "disabled"),
    Output("run-secret-scan-btn", "children"),
    Input("secret-scan-report-store", "data"),
    prevent_initial_call=True,
)
def render_secret_scan_results(report):
    """Render the secret scan findings from the completed report."""
    if not report:
        return no_update, no_update, no_update, no_update

    # Handle error case
    if "error" in report:
        error_card = dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.I(className="fas fa-times-circle text-danger me-2",
                           style={"fontSize": "2rem"}),
                    html.Span(f"Scan failed: {report['error']}", className="text-danger"),
                ], className="text-center py-5 d-flex align-items-center justify-content-center")
            ])
        ], className="bg-dark border-danger")
        btn_children = [html.I(className="fas fa-redo me-2"), "Retry Secret Scan"]
        return html.Div(), error_card, False, btn_children

    findings = report.get("findings", [])
    total = report.get("total_findings", 0)
    buckets_scanned = report.get("buckets_scanned", 0)
    objects_scanned = report.get("objects_scanned", 0)
    scan_mode = report.get("scan_mode", "pattern")

    # Scan mode badge
    mode_info = {
        "trufflehog": ("🐷 TruffleHog", "danger"),
        "pattern": ("📄 Pattern Match", "info"),
        "mock": ("🧪 Mock Data", "secondary"),
    }
    mode_label, mode_color = mode_info.get(scan_mode, ("Unknown", "secondary"))

    # Count by source
    th_count = sum(1 for f in findings if f.get("source") == "trufflehog")
    pat_count = sum(1 for f in findings if f.get("source") == "pattern")

    # ── Summary cards ─────────────────────────────────────────────────────
    summary = html.Div([
        # Scan mode badge
        dbc.Row([
            dbc.Col([
                dbc.Badge(
                    mode_label,
                    color=mode_color,
                    className="me-2 p-2",
                    style={"fontSize": "0.85rem"},
                ),
                dbc.Badge(
                    f"TruffleHog: {th_count}",
                    color="danger",
                    className="me-1",
                ) if th_count else html.Span(),
                dbc.Badge(
                    f"Pattern: {pat_count}",
                    color="info",
                    className="me-1",
                ) if pat_count else html.Span(),
            ], className="mb-2"),
        ]),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H3(total, className="text-danger mb-0"),
                    html.Small("Sensitive Files Found", className="text-muted"),
                ], className="text-center py-2")
            ], className="bg-dark border-danger"), md=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H3(buckets_scanned, className="text-info mb-0"),
                    html.Small("Buckets Scanned", className="text-muted"),
                ], className="text-center py-2")
            ], className="bg-dark border-info"), md=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H3(objects_scanned, className="text-primary mb-0"),
                    html.Small("Objects Inspected", className="text-muted"),
                ], className="text-center py-2")
            ], className="bg-dark border-primary"), md=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H3(
                        len(set(f["bucket"] for f in findings)),
                        className="text-warning mb-0",
                    ),
                    html.Small("Affected Buckets", className="text-muted"),
                ], className="text-center py-2")
            ], className="bg-dark border-warning"), md=3),
        ], className="mb-4"),
    ])

    # ── Findings table ────────────────────────────────────────────────────
    if not findings:
        results_card = dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.I(className="fas fa-check-circle text-success me-2",
                           style={"fontSize": "2rem"}),
                    html.Span("No sensitive files found — your buckets look clean!",
                              className="text-success"),
                ], className="text-center py-5 d-flex align-items-center justify-content-center")
            ])
        ], className="bg-dark border-secondary")
    else:
        # Build OCI Console base URL from report metadata
        ns = report.get("namespace", "")
        region = report.get("region", "us-ashburn-1")

        rows = []
        for idx, f in enumerate(findings, start=1):
            source = f.get("source", "pattern")
            if source == "trufflehog":
                source_badge = dbc.Badge(
                    "🐷 TH", color="danger", className="px-2",
                    style={"fontSize": "0.7rem"},
                )
            elif source == "content":
                source_badge = dbc.Badge(
                    "🔍 Content", color="warning", className="px-2",
                    style={"fontSize": "0.7rem"},
                )
            else:
                source_badge = dbc.Badge(
                    "📄 Name", color="info", className="px-2",
                    style={"fontSize": "0.7rem"},
                )

            # For content findings, show the redacted snippet
            raw_snippet = f.get("raw_result", "")
            finding_type_el = dbc.Badge(
                f["finding_type"], color="danger", className="text-wrap",
                style={"fontSize": "0.75rem"},
                title=raw_snippet if raw_snippet else None,
            )

            # Local download route — streams the object via OCI SDK
            bucket = f["bucket"]
            obj_name = f["file_name"]
            download_url = (
                f"/download-object"
                f"?ns={urlquote(ns, safe='')}"
                f"&bucket={urlquote(bucket, safe='')}"
                f"&object={urlquote(obj_name, safe='')}"
                f"&region={urlquote(region, safe='')}"
            )

            rows.append(html.Tr([
                html.Td(idx, className="text-muted"),
                html.Td([
                    html.I(className="fas fa-exclamation-triangle text-danger me-2"),
                ]),
                html.Td([
                    html.Code(f["file_name"], className="text-warning"),
                ]),
                html.Td(f["bucket"]),
                html.Td(f["compartment"]),
                html.Td(finding_type_el),
                html.Td(source_badge),
                html.Td(_format_file_size(f.get("file_size"))),
                html.Td(
                    html.A(
                        html.I(className="fas fa-download"),
                        href=download_url,
                        target="_blank",
                        className="text-info",
                        title=f"Download {obj_name}",
                    ),
                    className="text-center",
                ),
            ]))

        results_card = dbc.Card([
            dbc.CardHeader([
                dbc.Row([
                    dbc.Col([
                        html.I(className="fas fa-exclamation-triangle text-danger me-2"),
                        f"Sensitive Files Found — {total} result{'s' if total != 1 else ''}"
                    ]),
                    dbc.Col([
                        html.Small(
                            f"Scanned at {report.get('completed_at', '—')[:19].replace('T', ' ')}",
                            className="text-muted float-end",
                        )
                    ], className="text-end"),
                ])
            ]),
            dbc.CardBody([
                dbc.Table([
                    html.Thead(html.Tr([
                        html.Th("#", style={"width": "40px"}),
                        html.Th("", style={"width": "30px"}),
                        html.Th("File Name"),
                        html.Th("Bucket"),
                        html.Th("Compartment"),
                        html.Th("Type"),
                        html.Th("Source", style={"width": "65px"}),
                        html.Th("Size", style={"width": "90px"}),
                        html.Th("Link", style={"width": "50px"}),
                    ])),
                    html.Tbody(rows),
                ], bordered=True, color="dark", hover=True, responsive=True, size="sm",
                   className="mb-0"),
            ]),
        ], className="bg-dark border-secondary")

    # Reset button label
    btn_children = [
        html.I(className="fas fa-redo me-2"),
        "Re-run Secret Scan",
    ]

    return summary, results_card, False, btn_children


# ── CIS Callback 1: Start scan ───────────────────────────────────────────────
@callback(
    Output("cis-run-btn", "disabled", allow_duplicate=True),
    Output("cis-run-btn", "children", allow_duplicate=True),
    Output("cis-poll-interval", "disabled", allow_duplicate=True),
    Input("cis-run-btn", "n_clicks"),
    prevent_initial_call=True,
)
def start_cis_benchmark(n_clicks):
    if not n_clicks:
        return no_update, no_update, no_update
    if _bg_cis_state["running"]:
        return True, no_update, no_update

    def _worker():
        try:
            _bg_cis_state["running"] = True
            _bg_cis_state["report"] = None
            _bg_cis_state["error"] = None
            _bg_cis_state["progress"] = "Starting CIS benchmark…"

            collector = None
            try:
                collector = OCICollector()
                if not collector.config:
                    collector = None
            except Exception:
                collector = None

            def _on_progress(msg):
                _bg_cis_state["progress"] = msg

            result = run_cis_benchmark(
                collector=collector,
                progress_callback=_on_progress,
            )
            _bg_cis_state["report"] = result
        except Exception as e:
            _bg_cis_state["error"] = str(e)
            logger.error("CIS benchmark error: %s", e)
        finally:
            _bg_cis_state["running"] = False

    threading.Thread(target=_worker, daemon=True).start()

    btn = [
        dbc.Spinner(size="sm", spinner_class_name="me-2"),
        "Running CIS Benchmark…",
    ]
    return True, btn, False   # disable btn, start polling


# ── CIS Callback 2: Poll for results ─────────────────────────────────────────
@callback(
    Output("cis-report-store", "data"),
    Output("cis-poll-interval", "disabled"),
    Output("cis-progress-area", "children"),
    Input("cis-poll-interval", "n_intervals"),
    prevent_initial_call=True,
)
def poll_cis_benchmark(n_intervals):
    progress_bar = dbc.Progress(
        value=100, striped=True, animated=True, className="mb-2",
        label=_bg_cis_state.get("progress", ""),
        style={"height": "22px"},
    )

    if _bg_cis_state["running"]:
        return no_update, False, progress_bar

    report = _bg_cis_state.get("report")
    if report:
        return report, True, []   # stop polling, clear progress

    error = _bg_cis_state.get("error")
    if error:
        return no_update, True, dbc.Alert(f"Error: {error}", color="danger")

    return no_update, True, []


# ── CIS Callback 3: Render results ───────────────────────────────────────────
@callback(
    Output("cis-results-area", "children"),
    Output("cis-run-btn", "disabled", allow_duplicate=True),
    Output("cis-run-btn", "children", allow_duplicate=True),
    Input("cis-report-store", "data"),
    prevent_initial_call=True,
)
def render_cis_results(report):
    if not report:
        return no_update, no_update, no_update

    passed = report.get("passed", 0)
    failed = report.get("failed", 0)
    errors = report.get("errors", 0)
    skipped = report.get("skipped", 0)
    total = report.get("total_checks", 0)
    pct = report.get("compliance_pct", 0)
    scan_mode = report.get("scan_mode", "")

    # ── Compliance score color ──
    if pct >= 80:
        score_color = "success"
    elif pct >= 50:
        score_color = "warning"
    else:
        score_color = "danger"

    mode_badge = dbc.Badge(
        scan_mode.upper(), color="info" if scan_mode == "live" else "secondary",
        className="ms-2",
    )

    # ── Summary cards row ──
    summary = dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H2(f"{pct}%", className=f"text-{score_color} mb-0",
                         style={"fontSize": "2.5rem", "fontWeight": "700"}),
                html.Small("Compliance", className="text-muted"),
            ], className="text-center py-2")
        ], className="bg-dark border-secondary"), md=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H2(str(passed), className="text-success mb-0",
                         style={"fontSize": "2.5rem", "fontWeight": "700"}),
                html.Small("Passed", className="text-muted"),
            ], className="text-center py-2")
        ], className="bg-dark border-secondary"), md=2),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H2(str(failed), className="text-danger mb-0",
                         style={"fontSize": "2.5rem", "fontWeight": "700"}),
                html.Small("Failed", className="text-muted"),
            ], className="text-center py-2")
        ], className="bg-dark border-secondary"), md=2),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H2(str(errors), className="text-warning mb-0",
                         style={"fontSize": "2.5rem", "fontWeight": "700"}),
                html.Small("Errors", className="text-muted"),
            ], className="text-center py-2")
        ], className="bg-dark border-secondary"), md=2),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H2(str(total), className="text-info mb-0",
                         style={"fontSize": "2.5rem", "fontWeight": "700"}),
                html.Small(["Total Checks", mode_badge], className="text-muted"),
            ], className="text-center py-2")
        ], className="bg-dark border-secondary"), md=3),
    ], className="mb-3")

    # ── Category breakdown ──
    categories = {}
    for r in report.get("results", []):
        cat = r.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0, "error": 0}
        if r["status"] == "PASS":
            categories[cat]["pass"] += 1
        elif r["status"] == "FAIL":
            categories[cat]["fail"] += 1
        else:
            categories[cat]["error"] += 1

    cat_badges = []
    cat_icons = {
        "Identity & Access Management": "fas fa-users-cog",
        "Networking": "fas fa-network-wired",
        "Storage": "fas fa-database",
        "Compute": "fas fa-server",
        "Logging & Monitoring": "fas fa-clipboard-list",
    }
    for cat, counts in categories.items():
        icon = cat_icons.get(cat, "fas fa-check-circle")
        cat_total = counts["pass"] + counts["fail"] + counts["error"]
        cat_pass_pct = round(100 * counts["pass"] / cat_total) if cat_total else 0
        color = "success" if cat_pass_pct >= 80 else ("warning" if cat_pass_pct >= 50 else "danger")
        cat_badges.append(
            dbc.Col(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className=f"{icon} me-2"),
                            html.Strong(cat),
                        ]),
                        dbc.Progress(
                            value=cat_pass_pct,
                            color=color,
                            className="mt-2",
                            style={"height": "8px"},
                        ),
                        html.Small(
                            f"{counts['pass']}/{cat_total} passed",
                            className="text-muted",
                        ),
                    ], className="py-2")
                ], className="bg-dark border-secondary"),
                className="mb-2",
            )
        )

    cat_row = dbc.Row(cat_badges, className="mb-3")

    # ── Findings table ──
    severity_colors = {
        "critical": "danger",
        "high": "warning",
        "medium": "info",
        "low": "success",
    }
    status_icons = {
        "PASS": ("✅", "success"),
        "FAIL": ("❌", "danger"),
        "ERROR": ("⚠️", "warning"),
        "SKIPPED": ("⏭", "secondary"),
    }

    rows = []
    for r in report.get("results", []):
        icon, status_color = status_icons.get(r["status"], ("?", "secondary"))
        sev_color = severity_colors.get(r["severity"], "secondary")

        # Resource list (collapsible if many)
        resources = r.get("affected_resources", [])
        if resources:
            res_content = html.Ul(
                [html.Li(res, style={"fontSize": "0.75rem"}) for res in resources[:5]],
                className="mb-0 ps-3",
            )
            if len(resources) > 5:
                res_content = html.Div([
                    res_content,
                    html.Small(
                        f"… and {len(resources) - 5} more",
                        className="text-muted",
                    ),
                ])
        else:
            res_content = html.Small("—", className="text-muted")

        rows.append(
            html.Tr([
                html.Td(
                    html.Span(icon, style={"fontSize": "1.1rem"}),
                    style={"width": "40px", "textAlign": "center"},
                ),
                html.Td([
                    dbc.Badge(r["check_id"], color="dark",
                              className="me-2", style={"fontSize": "0.7rem"}),
                ], style={"width": "80px"}),
                html.Td([
                    html.Div(r["title"], style={"fontWeight": "500"}),
                    html.Small(r.get("evidence", ""), className="text-muted"),
                ]),
                html.Td(
                    dbc.Badge(r["severity"].upper(), color=sev_color,
                              style={"fontSize": "0.7rem"}),
                    style={"width": "90px"},
                ),
                html.Td(
                    dbc.Badge(r["category"].split(" ")[0], color="dark",
                              className="text-wrap",
                              style={"fontSize": "0.65rem"}),
                    style={"width": "80px"},
                ),
                html.Td(res_content),
            ], className=f"{'table-danger' if r['status'] == 'FAIL' else ''}")
        )

    findings_table = dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-list-check me-2"),
            f"CIS OCI Benchmark — {total} Checks",
        ]),
        dbc.CardBody([
            dbc.Table([
                html.Thead(
                    html.Tr([
                        html.Th("", style={"width": "40px"}),
                        html.Th("ID", style={"width": "80px"}),
                        html.Th("Check"),
                        html.Th("Severity", style={"width": "90px"}),
                        html.Th("Category", style={"width": "80px"}),
                        html.Th("Affected Resources"),
                    ])
                ),
                html.Tbody(rows),
            ], bordered=True, hover=True, responsive=True, size="sm",
               className="table-dark mb-0"),
        ]),
    ], className="bg-dark border-secondary")

    # Re-enable button
    btn_children = [
        html.I(className="fas fa-redo me-2"),
        "Re-run CIS Benchmark",
    ]

    return [summary, cat_row, findings_table], False, btn_children
