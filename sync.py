"""
LynxMap - OCI Sync Utility
Syncs data from OCI to the local database
"""
import sys
import logging
from collectors.oci_collector import OCICollector
from db.database import import_assets, init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("LynxMap-Sync")

def sync():
    """Run the synchronization process"""
    logger.info("Initializing database...")
    init_database()
    
    logger.info("Starting OCI collection...")
    # Initialize collector (will use ~/.oci/config by default)
    collector = OCICollector()
    
    # Collect assets from OCI (or mock data if OCI SDK not configured)
    assets = collector.collect_all()
    
    if not assets:
        logger.warning("No assets collected.")
        return
        
    logger.info(f"Importing {len(assets)} assets into database...")
    stats = import_assets(assets, source_description="OCI API Sync")
    
    logger.info("Sync complete!")
    logger.info(f"Stats: {stats}")

if __name__ == "__main__":
    sync()
