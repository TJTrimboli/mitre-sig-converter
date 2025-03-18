#!/usr/bin/env python3
from mitre_sig_converter.api import MitreApi
from mitre_sig_converter.utils import setup_logger, FileHandler
from pathlib import Path
import argparse
import sys
import json
from datetime import datetime, UTC

def parse_args():
    parser = argparse.ArgumentParser(description='Download and cache MITRE ATT&CK data')
    parser.add_argument('--output-dir', type=str, default='data/mitre',
                       help='Output directory for MITRE data (default: data/mitre)')
    parser.add_argument('--log-file', type=str, default='logs/download_mitre.log',
                       help='Log file path (default: logs/download_mitre.log)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Setup logging
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = setup_logger('download_mitre', args.log_file)
    
    try:
        # Initialize MITRE API client and file handler
        mitre_api = MitreApi()
        file_handler = FileHandler()
        
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Download enterprise matrix
        logger.info("Downloading MITRE ATT&CK Enterprise Matrix...")
        matrix = mitre_api.get_enterprise_matrix()
        matrix_file = output_dir / 'enterprise_matrix.json'
        file_handler.write_json(matrix, matrix_file)
        logger.info(f"Enterprise matrix saved to {matrix_file}")
        
        # Download all techniques
        logger.info("Downloading MITRE ATT&CK Techniques...")
        techniques = mitre_api.get_all_techniques()
        techniques_file = output_dir / 'techniques.json'
        file_handler.write_json(techniques, techniques_file)
        logger.info(f"Found {len(techniques)} techniques, saved to {techniques_file}")
        
        # Download tactics
        logger.info("Downloading MITRE ATT&CK Tactics...")
        tactics = mitre_api.get_tactics()
        tactics_file = output_dir / 'tactics.json'
        file_handler.write_json(tactics, tactics_file)
        logger.info(f"Found {len(tactics)} tactics, saved to {tactics_file}")
        
        # Create metadata file
        metadata = {
            'last_updated': str(datetime.now(UTC)),
            'version': mitre_api.VERSION,
            'files': {
                'enterprise_matrix': str(matrix_file),
                'techniques': str(techniques_file),
                'tactics': str(tactics_file)
            }
        }
        metadata_file = output_dir / 'metadata.json'
        file_handler.write_json(metadata, metadata_file)
        logger.info(f"Metadata saved to {metadata_file}")
        
        logger.info("MITRE ATT&CK data download completed successfully")
        
    except Exception as e:
        logger.error(f"Error downloading MITRE data: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
