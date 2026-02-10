import unittest
import sys
import os
import json
import sqlite3
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.oci_collector import OCICollector
from db.database import import_assets, init_database, get_connection

class TestOCICollector(unittest.TestCase):
    
    def test_mock_collection_structure(self):
        """Test that mock data follows the correct asset schema"""
        collector = OCICollector()
        # Force config to None to trigger mock data execution
        collector.config = None
        
        assets = collector.collect_all()
        
        self.assertIsInstance(assets, list)
        self.assertGreater(len(assets), 0)
        
        asset = assets[0]
        self.assertIn('asset_id', asset)
        self.assertIn('asset_type', asset)
        self.assertIn('name', asset)
        self.assertIn('compartment', asset)
        self.assertIn('metadata', asset)
        self.assertIsInstance(asset['metadata'], dict)

    @patch('collectors.oci_collector.oci', create=True)
    def test_instance_normalization(self, mock_oci):
        """Test normalization of instance data"""
        collector = OCICollector()
        collector.config = {"region": "us-ashburn-1"}
        
        # Mock Compute Client
        mock_compute = MagicMock()
        collector.clients["compute"] = mock_compute
        
        # Mock instance object
        mock_inst = MagicMock()
        mock_inst.id = "ocid1.instance.oc1..test"
        mock_inst.display_name = "Test-VM"
        mock_inst.region = "us-ashburn-1"
        mock_inst.shape = "VM.Standard2.1"
        mock_inst.lifecycle_state = "RUNNING"
        mock_inst.availability_domain = "AD-1"
        mock_inst.time_created = "2023-01-01T00:00:00Z"
        
        # Setup return value
        mock_response = MagicMock()
        mock_response.data = [mock_inst]
        mock_compute.list_instances.return_value = mock_response
        
        # Execute
        results = collector._collect_instances("comp-id", "comp-name")
        
        self.assertEqual(len(results), 1)
        asset = results[0]
        self.assertEqual(asset['asset_id'], "ocid1.instance.oc1..test")
        self.assertEqual(asset['asset_type'], "vm")
        self.assertEqual(asset['name'], "Test-VM")
        self.assertEqual(asset['metadata']['shape'], "VM.Standard2.1")


class TestDatabase(unittest.TestCase):
    
    def setUp(self):
        # Create an in-memory database for testing
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        
        # Initialize schema manually since init_database uses hardcoded path
        cursor = self.conn.cursor()
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT,
                total_assets INTEGER,
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT
            )
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    @patch('db.database.get_connection')
    def test_import_assets(self, mock_get_conn):
        """Test importing assets into database"""
        mock_get_conn.return_value.__enter__.return_value = self.conn
        
        assets = [
            {
                "asset_id": "test-vm-1",
                "asset_type": "vm",
                "name": "Production VM",
                "compartment": "Production",
                "region": "us-phoenix-1",
                "scan_status": "scanned",
                "risk_score": 50,
                "metadata": {"cpu": 4, "ram": 32}
            },
            {
                "asset_id": "test-bucket-1",
                "asset_type": "bucket",
                "name": "Logs Bucket",
                "compartment": "Audit",
                "region": "us-ashburn-1",
                "metadata": {"public_access": "NoPublicAccess"}
            }
        ]
        
        stats = import_assets(assets, "Test Import")
        
        self.assertEqual(stats['imported'], 2)
        self.assertEqual(stats['errors'], 0)
        self.assertEqual(stats['by_type']['vm'], 1)
        self.assertEqual(stats['by_type']['bucket'], 1)
        
        # Verify in DB
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_id='test-vm-1'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row['name'], "Production VM")
        self.assertEqual(row['risk_score'], 50)
        
        # Check metadata JSON storage
        meta = json.loads(row['metadata'])
        self.assertEqual(meta['cpu'], 4)

    @patch('db.database.get_connection')
    def test_upsert_behavior(self, mock_get_conn):
        """Test that re-importing updates existing records"""
        mock_get_conn.return_value.__enter__.return_value = self.conn
        
        # Initial import
        assets_v1 = [{
            "asset_id": "test-vm-1",
            "asset_type": "vm",
            "name": "Old Name",
            "compartment": "Dev",
            "risk_score": 10
        }]
        import_assets(assets_v1, "Import V1")
        
        # Update import
        assets_v2 = [{
            "asset_id": "test-vm-1",
            "asset_type": "vm",
            "name": "New Name", # Changed
            "compartment": "Prod", # Changed
            "risk_score": 90 # Changed
        }]
        stats = import_assets(assets_v2, "Import V2")
        
        self.assertEqual(stats['imported'], 1) 
        
        # Verify update
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_id='test-vm-1'")
        row = cursor.fetchone()
        self.assertEqual(row['name'], "New Name")
        self.assertEqual(row['compartment'], "Prod")
        self.assertEqual(row['risk_score'], 90)

if __name__ == '__main__':
    unittest.main()
