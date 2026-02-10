"""
LynxMap - Playbooks Page (Security Scanning Interface)
Interface for running CIS benchmarks and viewing scan results
"""

import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc
from datetime import datetime

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


# Page layout
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


# Callbacks
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
