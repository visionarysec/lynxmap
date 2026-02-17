"""
LynxMap - Database Module
SQLite database for storing OCI asset inventory
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import contextmanager

# Database file location
DB_DIR = Path(__file__).parent.parent
DB_FILE = DB_DIR / "lynxmap.db"


def get_db_path() -> Path:
    """Get the database file path"""
    return DB_FILE


@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize the database schema"""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Assets table - main inventory
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT UNIQUE NOT NULL,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                compartment TEXT,
                region TEXT,
                metadata TEXT,
                scan_status TEXT DEFAULT 'not_scanned',
                risk_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for faster queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_type ON assets(asset_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_compartment ON assets(compartment)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_region ON assets(region)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON assets(scan_status)")
        
        # Scan results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT,
                message TEXT,
                remediation TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_asset ON scan_results(asset_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_results(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_severity ON scan_results(severity)")
        
        # Compartments table for hierarchy
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compartments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                compartment_id TEXT UNIQUE,
                name TEXT NOT NULL,
                parent_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Import history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT,
                total_assets INTEGER,
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT
            )
        """)
        
        conn.commit()
        print(f"✅ Database initialized at {DB_FILE}")


def import_assets(assets: List[Dict], source_description: str = "API Import") -> Dict[str, Any]:
    """
    Import assets from list of dictionaries into database
    Returns import statistics
    """
    stats = {
        'total': len(assets),
        'imported': 0,
        'updated': 0,
        'errors': 0,
        'by_type': {}
    }
    
    with get_connection() as conn:
        cursor = conn.cursor()
        
        for asset in assets:
            try:
                asset_type = asset.get('asset_type', 'unknown')
                
                # Track by type
                if asset_type not in stats['by_type']:
                    stats['by_type'][asset_type] = 0
                
                # Prepare metadata as JSON string
                meta_raw = asset.get('metadata', {})
                if isinstance(meta_raw, dict):
                    metadata = json.dumps(meta_raw)
                else:
                    metadata = str(meta_raw)
                
                # Upsert: Insert or update if exists
                cursor.execute("""
                    INSERT INTO assets (asset_id, asset_type, name, compartment, region, metadata, scan_status, risk_score, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        name = excluded.name,
                        compartment = excluded.compartment,
                        region = excluded.region,
                        metadata = excluded.metadata,
                        risk_score = excluded.risk_score,
                        updated_at = excluded.updated_at
                """, (
                    asset.get('asset_id'),
                    asset_type,
                    asset.get('name'),
                    asset.get('compartment'),
                    asset.get('region'),
                    metadata,
                    asset.get('scan_status', 'not_scanned'),
                    asset.get('risk_score', 0),
                    datetime.now().isoformat()
                ))
                
                stats['imported'] += 1
                stats['by_type'][asset_type] += 1
                    
            except Exception as e:
                stats['errors'] += 1
                print(f"Error importing asset {asset.get('asset_id', 'unknown')}: {e}")
        
        # Record import history
        cursor.execute("""
            INSERT INTO import_history (source_file, total_assets, status)
            VALUES (?, ?, ?)
        """, (source_description, stats['imported'], 'success' if stats['errors'] == 0 else 'partial'))
        
        conn.commit()
    
    return stats


def import_from_json(json_path: str) -> Dict[str, Any]:
    """
    Import assets from JSON file into database
    Returns import statistics
    """
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Handle list or dict wrapper
    if isinstance(data, list):
        assets = data
    else:
        assets = data.get('assets', [])
        
    return import_assets(assets, source_description=json_path)


def get_asset_summary() -> Dict[str, int]:
    """Get count of assets by type"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT asset_type, COUNT(*) as count
            FROM assets
            GROUP BY asset_type
            ORDER BY count DESC
        """)
        return {row['asset_type']: row['count'] for row in cursor.fetchall()}


def get_assets_by_type(asset_type: str, limit: int = 100, offset: int = 0) -> List[Dict]:
    """Get assets filtered by type"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assets
            WHERE asset_type = ?
            ORDER BY name
            LIMIT ? OFFSET ?
        """, (asset_type, limit, offset))
        return [dict(row) for row in cursor.fetchall()]


def get_compartment_summary() -> Dict[str, int]:
    """Get count of assets by compartment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT compartment, COUNT(*) as count
            FROM assets
            GROUP BY compartment
            ORDER BY count DESC
        """)
        return {row['compartment']: row['count'] for row in cursor.fetchall()}


def get_region_summary() -> Dict[str, int]:
    """Get count of assets by region"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT region, COUNT(*) as count
            FROM assets
            GROUP BY region
            ORDER BY count DESC
        """)
        return {row['region']: row['count'] for row in cursor.fetchall()}


def get_all_assets(limit: int = 1000, offset: int = 0) -> List[Dict]:
    """Get all assets with pagination"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assets
            ORDER BY asset_type, name
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]


def get_total_asset_count() -> int:
    """Get total count of assets"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM assets")
        return cursor.fetchone()['count']


def search_assets(query: str, limit: int = 50) -> List[Dict]:
    """Search assets by name or asset_id"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assets
            WHERE name LIKE ? OR asset_id LIKE ?
            ORDER BY name
            LIMIT ?
        """, (f'%{query}%', f'%{query}%', limit))
        return [dict(row) for row in cursor.fetchall()]


def get_hierarchy_data() -> Dict:
    """Get hierarchical data for sunburst visualization"""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Get compartment -> asset_type -> assets hierarchy
        cursor.execute("""
            SELECT compartment, asset_type, COUNT(*) as count
            FROM assets
            GROUP BY compartment, asset_type
            ORDER BY compartment, asset_type
        """)
        
        hierarchy = {}
        for row in cursor.fetchall():
            comp = row['compartment'] or 'unknown'
            atype = row['asset_type']
            count = row['count']
            
            if comp not in hierarchy:
                hierarchy[comp] = {}
            hierarchy[comp][atype] = count
        
        return hierarchy


def clear_database():
    """Clear all data from database (use with caution)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_results")
        cursor.execute("DELETE FROM assets")
        cursor.execute("DELETE FROM compartments")
        conn.commit()
        print("✅ Database cleared")


def import_compartments_from_csv(csv_path: str) -> int:
    """Import compartments from CSV file"""
    import csv
    
    compartments = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            compartments.append({
                'name': row.get('Name', ''),
                'compartment_id': row.get('CompartmentId', ''),
                'parent_id': row.get('ParentCompartment', '')
            })
    
    with get_connection() as conn:
        cursor = conn.cursor()
        
        for comp in compartments:
            try:
                cursor.execute("""
                    INSERT INTO compartments (compartment_id, name, parent_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(compartment_id) DO UPDATE SET
                        name = excluded.name,
                        parent_id = excluded.parent_id
                """, (comp['compartment_id'], comp['name'], comp['parent_id']))
            except Exception as e:
                print(f"Error importing compartment {comp['name']}: {e}")
        
        conn.commit()
    
    return len(compartments)


def import_compartments(compartments: List[Dict]) -> int:
    """
    Import list of compartment dictionaries into database
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        count = 0
        for comp in compartments:
            try:
                cursor.execute("""
                    INSERT INTO compartments (compartment_id, name, parent_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(compartment_id) DO UPDATE SET
                        name = excluded.name,
                        parent_id = excluded.parent_id
                """, (comp['id'], comp['name'], comp.get('parent_compartment_id')))
                count += 1
            except Exception as e:
                print(f"Error importing compartment {comp.get('name')}: {e}")
        
        conn.commit()
    
    return count


def get_compartments_for_sunburst() -> Dict[str, Any]:
    """Get compartment hierarchy data for sunburst chart"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT compartment_id, name, parent_id FROM compartments")
        rows = cursor.fetchall()
    
    # Build dataframe-like structure
    ids = []
    labels = []
    parents = []
    
    # Set of all known compartment IDs
    all_known_ids = set(row['compartment_id'] for row in rows)
    
    # Find the actual Tenancy root (node with no parent)
    tenancy_id = None
    for row in rows:
        if not row['parent_id']:
            tenancy_id = row['compartment_id']
            break
            
    # Add all known compartments
    for row in rows:
        ids.append(row['compartment_id'])
        labels.append(row['name'])
        # If parent is empty, keep it empty (root)
        parents.append(row['parent_id'] if row['parent_id'] else "")
        
    # Handle missing parents (orphans' parents that aren't in the DB)
    # Get all distinct parent IDs referenced by children
    referenced_parents = set(row['parent_id'] for row in rows if row['parent_id'])
    
    for pid in referenced_parents:
        if pid not in all_known_ids:
            # This parent is referenced but not in our DB
            ids.append(pid)
            labels.append(f"Unknown Parent ({pid[-6:]})")
            # Link to tenancy if we have one, otherwise make it a root
            parents.append(tenancy_id if tenancy_id else "")
            all_known_ids.add(pid) # Mark as handled
    
    return {
        'ids': ids,
        'labels': labels,
        'parents': parents
    }


def get_assets_by_compartment_label(compartment_label: str) -> List[Dict]:
    """Get all assets for a compartment by name"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assets
            WHERE compartment = ?
            ORDER BY asset_type, name
        """, (compartment_label,))
        return [dict(row) for row in cursor.fetchall()]


def get_asset_counts_by_compartment(compartment_label: str) -> Dict[str, int]:
    """Get asset type counts for a specific compartment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT asset_type, COUNT(*) as count
            FROM assets
            WHERE compartment = ?
            GROUP BY asset_type
            ORDER BY count DESC
        """, (compartment_label,))
        return {row['asset_type']: row['count'] for row in cursor.fetchall()}


def get_assets_by_compartment_and_type(compartment_label: str, asset_type: str) -> List[Dict]:
    """Get assets filtered by compartment and type"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM assets
            WHERE compartment = ? AND asset_type = ?
            ORDER BY name
        """, (compartment_label, asset_type))
        return [dict(row) for row in cursor.fetchall()]


def get_asset_by_id(asset_id: str) -> Optional[Dict]:
    """Get a single asset by its asset_id"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_asset_by_name(name: str) -> Optional[Dict]:
    """Get a single asset by its name"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE name = ?", (name,))
        row = cursor.fetchone()
        return dict(row) if row else None


def calculate_blast_radius(asset: Dict) -> Dict[str, Any]:
    """
    Calculate the blast radius for a given asset.
    Returns direct connections (1 hop) and indirect connections (2+ hops).
    
    Blast radius is determined by:
    1. Same compartment (network proximity)
    2. Same region (can communicate)
    3. Asset type relationships (VM -> VNIC, LB -> VM, IAM -> all)
    """
    if not asset:
        return {"error": "Asset not found"}
    
    compartment = asset.get('compartment')
    region = asset.get('region')
    asset_type = asset.get('asset_type')
    asset_id = asset.get('asset_id')
    
    result = {
        'source_asset': asset,
        'direct_connections': [],  # 1 hop - same compartment
        'indirect_connections': [],  # 2+ hops - same region, different compartment
        'iam_exposure': [],  # IAM policies that could affect this asset
        'summary': {
            'total_impacted': 0,
            'by_type': {},
            'risk_level': 'low',
            'compartments_affected': set(),
            'regions_affected': set()
        }
    }
    
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Direct connections - same compartment, excluding self
        cursor.execute("""
            SELECT * FROM assets 
            WHERE compartment = ? AND asset_id != ?
            ORDER BY asset_type, name
        """, (compartment, asset_id))
        
        for row in cursor.fetchall():
            asset_dict = dict(row)
            # Calculate connection strength based on type relationship
            connection_strength = _calculate_connection_strength(asset_type, asset_dict['asset_type'])
            asset_dict['connection_strength'] = connection_strength
            asset_dict['connection_reason'] = f"Same compartment: {compartment}"
            result['direct_connections'].append(asset_dict)
            
            # Track in summary
            atype = asset_dict['asset_type']
            result['summary']['by_type'][atype] = result['summary']['by_type'].get(atype, 0) + 1
            result['summary']['compartments_affected'].add(compartment)
        
        # 2. Indirect connections - same region, different compartment
        cursor.execute("""
            SELECT * FROM assets 
            WHERE region = ? AND compartment != ? AND asset_id != ?
            ORDER BY compartment, asset_type, name
            LIMIT 100
        """, (region, compartment, asset_id))
        
        for row in cursor.fetchall():
            asset_dict = dict(row)
            connection_strength = _calculate_connection_strength(asset_type, asset_dict['asset_type']) * 0.5
            asset_dict['connection_strength'] = connection_strength
            asset_dict['connection_reason'] = f"Same region: {region}"
            result['indirect_connections'].append(asset_dict)
            result['summary']['compartments_affected'].add(asset_dict['compartment'])
        
        # 3. IAM exposure - find IAM policies in same compartment or parent
        cursor.execute("""
            SELECT * FROM assets 
            WHERE asset_type = 'iam' AND (compartment = ? OR region = ?)
            ORDER BY name
        """, (compartment, region))
        
        for row in cursor.fetchall():
            asset_dict = dict(row)
            asset_dict['connection_reason'] = "IAM policy with potential access"
            result['iam_exposure'].append(asset_dict)
    
    # Calculate totals
    result['summary']['total_impacted'] = (
        len(result['direct_connections']) + 
        len(result['indirect_connections'])
    )
    result['summary']['compartments_affected'] = list(result['summary']['compartments_affected'])
    result['summary']['regions_affected'] = [region] if region else []
    
    # Determine risk level based on impact
    total = result['summary']['total_impacted']
    if total > 100:
        result['summary']['risk_level'] = 'critical'
    elif total > 50:
        result['summary']['risk_level'] = 'high'
    elif total > 20:
        result['summary']['risk_level'] = 'medium'
    else:
        result['summary']['risk_level'] = 'low'
    
    return result


def _calculate_connection_strength(source_type: str, target_type: str) -> float:
    """
    Calculate connection strength between asset types.
    Higher values indicate stronger/more dangerous connections.
    """
    # Connection strength matrix (source -> target)
    # Scale: 0.0 (no connection) to 1.0 (critical connection)
    strength_matrix = {
        'vm': {
            'vnic': 1.0,      # VMs directly use VNICs
            'lb': 0.8,        # VMs are behind load balancers
            'bucket': 0.6,    # VMs may access buckets
            'iam': 0.9,       # IAM controls VM access
            'vm': 0.5,        # VM to VM communication
        },
        'vnic': {
            'vm': 1.0,        # VNICs are attached to VMs
            'lb': 0.7,        # VNICs route through LBs
            'vnic': 0.4,      # VNIC to VNIC in same subnet
            'bucket': 0.3,
            'iam': 0.5,
        },
        'lb': {
            'vm': 0.9,        # LBs route to VMs
            'vnic': 0.7,      # LBs use VNICs
            'lb': 0.3,
            'bucket': 0.2,
            'iam': 0.6,
        },
        'bucket': {
            'vm': 0.5,        # VMs access buckets
            'iam': 0.9,       # IAM controls bucket access
            'bucket': 0.2,
            'vnic': 0.1,
            'lb': 0.1,
        },
        'iam': {
            'vm': 0.9,        # IAM controls VMs
            'vnic': 0.7,
            'lb': 0.8,
            'bucket': 0.9,
            'iam': 0.5,
        },
    }
    
    source_connections = strength_matrix.get(source_type, {})
    return source_connections.get(target_type, 0.3)  # Default low connection


def get_blast_radius_graph_data(asset: Dict) -> Dict[str, Any]:
    """
    Generate network graph data for blast radius visualization.
    Returns nodes and edges for Plotly network graph.
    """
    blast_radius = calculate_blast_radius(asset)
    
    if 'error' in blast_radius:
        return blast_radius
    
    nodes = []
    edges = []
    
    # Source node (the selected asset)
    source = blast_radius['source_asset']
    nodes.append({
        'id': source['asset_id'],
        'label': source['name'][:30],
        'type': source['asset_type'],
        'group': 'source',
        'size': 30,
        'color': '#ff4444'
    })
    
    # Direct connection nodes (1 hop)
    for i, asset in enumerate(blast_radius['direct_connections'][:30]):  # Limit for visualization
        nodes.append({
            'id': asset['asset_id'],
            'label': asset['name'][:20],
            'type': asset['asset_type'],
            'group': 'direct',
            'size': 20,
            'color': _get_asset_color(asset['asset_type'])
        })
        edges.append({
            'source': source['asset_id'],
            'target': asset['asset_id'],
            'strength': asset['connection_strength'],
            'hop': 1
        })
    
    # Indirect connection nodes (2 hops) - sample for visualization
    for i, asset in enumerate(blast_radius['indirect_connections'][:20]):
        nodes.append({
            'id': asset['asset_id'],
            'label': asset['name'][:20],
            'type': asset['asset_type'],
            'group': 'indirect',
            'size': 15,
            'color': _get_asset_color(asset['asset_type'], faded=True)
        })
        # Connect to a random direct connection or source
        if blast_radius['direct_connections']:
            connector = blast_radius['direct_connections'][i % len(blast_radius['direct_connections'])]
            edges.append({
                'source': connector['asset_id'],
                'target': asset['asset_id'],
                'strength': asset['connection_strength'],
                'hop': 2
            })
    
    return {
        'nodes': nodes,
        'edges': edges,
        'summary': blast_radius['summary'],
        'direct_count': len(blast_radius['direct_connections']),
        'indirect_count': len(blast_radius['indirect_connections']),
        'iam_count': len(blast_radius['iam_exposure'])
    }


def _get_asset_color(asset_type: str, faded: bool = False) -> str:
    """Get color for asset type"""
    colors = {
        'vm': '#0d6efd',
        'vnic': '#0dcaf0',
        'bucket': '#ffc107',
        'iam': '#dc3545',
        'lb': '#198754',
    }
    color = colors.get(asset_type, '#6c757d')
    if faded:
        # Add transparency for indirect connections
        return color + '80'
    return color


def search_assets_for_blast_radius(query: str, limit: int = 20) -> List[Dict]:
    """Search assets for blast radius selection"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT asset_id, name, asset_type, compartment, region
            FROM assets
            WHERE name LIKE ? OR asset_id LIKE ?
            ORDER BY 
                CASE WHEN name LIKE ? THEN 0 ELSE 1 END,
                name
            LIMIT ?
        """, (f'%{query}%', f'%{query}%', f'{query}%', limit))
        return [dict(row) for row in cursor.fetchall()]


if __name__ == "__main__":
    # Initialize database
    init_database()
    
    # Test import if JSON file exists
    test_json = "/Users/satyam.dubey/Documents/Fedx-OCI/asm-oci/lynxmap_assets.json"
    if Path(test_json).exists():
        print(f"\n📥 Importing from {test_json}...")
        stats = import_from_json(test_json)
        print(f"\n📊 Import Statistics:")
        print(f"  Total assets: {stats['total']}")
        print(f"  Imported: {stats['imported']}")
        print(f"  Errors: {stats['errors']}")
        print(f"\n  By Type:")
        for atype, count in stats['by_type'].items():
            print(f"    {atype}: {count}")
        
        # Show summary
        print(f"\n📈 Asset Summary:")
        for atype, count in get_asset_summary().items():
            print(f"  {atype}: {count}")
