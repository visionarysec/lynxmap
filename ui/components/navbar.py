"""
LynxMap - Sidebar Navigation Component
Vertical navigation sidebar replacing the top navbar
"""

import dash
from dash import html
import dash_bootstrap_components as dbc


def create_sidebar():
    """Create the vertical sidebar navigation"""
    return html.Div(
        [
            # Logo / Brand
            html.Div(
                [
                    html.I(className="fas fa-shield-alt fa-2x me-2 text-info"),
                    html.H2("LynxMap", className="text-white mb-0"),
                ],
                className="d-flex align-items-center mb-4 px-3 py-3 border-bottom border-secondary"
            ),
            
            # Navigation Links
            dbc.Nav(
                [
                    dbc.NavLink(
                        [html.I(className="fas fa-home me-3"), "Dashboard"],
                        href="/",
                        active="exact",
                        className="sidebar-link mb-2"
                    ),
                    dbc.NavLink(
                        [html.I(className="fas fa-crosshairs me-3"), "Exposure"],
                        href="/exposure",
                        active="exact",
                        className="sidebar-link mb-2"
                    ),
                    dbc.NavLink(
                        [html.I(className="fas fa-radiation me-3"), "Blast Radius"],
                        href="/blast-radius",
                        active="exact",
                        className="sidebar-link mb-2"
                    ),
                    dbc.NavLink(
                        [html.I(className="fas fa-book me-3"), "Playbooks"],
                        href="/playbooks",
                        active="exact",
                        className="sidebar-link mb-2"
                    ),
                ],
                vertical=True,
                pills=True,
                className="px-3"
            ),
            
            # Bottom status
            html.Div(
                [
                    html.Hr(className="border-secondary my-3"),
                    html.Div(
                        [
                            html.Span(className="status-dot bg-success me-2"),
                            html.Span("OCI Connected", className="text-muted small")
                        ],
                        className="px-3"
                    )
                ],
                className="mt-auto pb-4"
            )
        ],
        className="sidebar bg-dark h-100 d-flex flex-column border-end border-secondary"
    )
