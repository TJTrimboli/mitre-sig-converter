#!/usr/bin/env python3
from mitre_sig_converter.database import DatabaseHandler
from mitre_sig_converter.utils import setup_logger, FileHandler
from mitre_sig_converter.api import MitreApi
from mitre_sig_converter.models import Technique as TechniqueModel
from pathlib import Path
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='Update MITRE ATT&CK techniques database')
    parser.add_argument('--db-url', type=str, default='sqlite:///data/techniques.db',
                       help='Database URL (default: sqlite:///data/techniques.db)')
    parser.add_argument('--log-file', type=str, default='logs/update_database.log',
                       help='Log file path (default: logs/update_database.log)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Setup logging
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = setup_logger('update_database', args.log_file)
    
    try:
        # Initialize database
        db = DatabaseHandler(args.db_url)
        db.init_db()
        logger.info("Database initialized successfully")
        
        # Initialize MITRE API client
        mitre_api = MitreApi()
        
        # Fetch all techniques
        logger.info("Fetching techniques from MITRE ATT&CK...")
        techniques = mitre_api.get_all_techniques()
        logger.info(f"Found {len(techniques)} techniques")
        
        # Update database
        for technique_data in techniques:
            technique_model = TechniqueModel.from_dict(technique_data)
            db_technique = {
                'technique_id': technique_model.technique_id,
                'name': technique_model.name,
                'description': technique_model.description,
                'platform': ','.join(technique_model.platforms) if technique_model.platforms else None
            }
            
            existing = db.get_technique(technique_model.technique_id)
            if existing:
                logger.debug(f"Updating technique {technique_model.technique_id}")
                db.update_technique(technique_model.technique_id, db_technique)
            else:
                logger.debug(f"Adding new technique {technique_model.technique_id}")
                db.add_technique(db_technique)
        
        logger.info("Database update completed successfully")
        
    except Exception as e:
        logger.error(f"Error updating database: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
