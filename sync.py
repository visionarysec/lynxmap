"""
LynxMap - OCI Sync Utility
Syncs data from OCI to the local database
"""
import sys
from pathlib import Path
import logging
from collectors.oci_collector import OCICollector
from db.database import import_assets, import_compartments, init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("LynxMap-Sync")

# Lock file for sync status
LOCK_FILE = Path(".sync_lock")

def sync():
    """Run the synchronization process"""
    if LOCK_FILE.exists():
        logger.warning("Sync already in progress (lock file exists). Exiting.")
        return

    try:
        LOCK_FILE.touch()
        logger.info("Initializing database...")
        init_database()
        
        logger.info("Starting OCI collection...")
        # Initialize collector (will use ~/.oci/config by default)
        collector = OCICollector()
        
        # Collect assets from OCI (or mock data if OCI SDK not configured)
        # Now returns a generator that yields batches of assets
        total_stats = {
            'total': 0,
            'imported': 0,
            'updated': 0,
            'errors': 0,
            'by_type': {}
        }
        
        # Start generator to trigger compartment collection
        asset_generator = collector.collect_all()
        
        # Iterating through the generator
        for batch in asset_generator:
            # If this is the FIRST batch, we should import compartments now that they are collected
            if collector.compartments and total_stats['total'] == 0:
                 logger.info(f"Importing {len(collector.compartments)} compartments...")
                 import_compartments(collector.compartments)
            
            if not batch:
                continue
                
            logger.info(f"Importing batch of {len(batch)} assets...")
            stats = import_assets(batch, source_description="OCI API Sync")
            
            # Update total stats
            total_stats['total'] += stats['total']
            total_stats['imported'] += stats['imported']
            total_stats['updated'] += stats['updated']
            total_stats['errors'] += stats['errors']
            
            for atype, count in stats['by_type'].items():
                total_stats['by_type'][atype] = total_stats['by_type'].get(atype, 0) + count
                    
    except Exception as e:
        logger.error(f"Error during synchronization: {e}")
    finally:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
        
    logger.info("Sync complete!")
    logger.info(f"Total Stats: {total_stats}")

if __name__ == "__main__":
    sync()
