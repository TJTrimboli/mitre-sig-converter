#!/usr/bin/env python3
from mitre_sig_converter.database import DatabaseHandler
from mitre_sig_converter.utils import setup_logger, FileHandler
from mitre_sig_converter.converter import YaraConverter, SigmaConverter, KqlConverter
from pathlib import Path
import argparse
import sys
import json
from datetime import datetime, UTC

def parse_args():
    parser = argparse.ArgumentParser(description='Generate signatures for MITRE ATT&CK techniques')
    parser.add_argument('--db-url', type=str, default='sqlite:///data/techniques.db',
                       help='Database URL (default: sqlite:///data/techniques.db)')
    parser.add_argument('--output-dir', type=str, default='output',
                       help='Output directory for generated signatures (default: output)')
    parser.add_argument('--log-file', type=str, default='logs/generate_signatures.log',
                       help='Log file path (default: logs/generate_signatures.log)')
    parser.add_argument('--technique-id', type=str,
                       help='Generate signatures for specific technique ID (optional)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Setup logging
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = setup_logger('generate_signatures', args.log_file)
    
    try:
        # Initialize database and converters
        db = DatabaseHandler(args.db_url)
        converters = {
            'yara': YaraConverter(),
            'sigma': SigmaConverter(),
            'kql': KqlConverter()
        }
        
        # Create output directories
        output_dir = Path(args.output_dir)
        for converter_type in converters.keys():
            (output_dir / converter_type).mkdir(parents=True, exist_ok=True)
        
        # Get techniques to process
        if args.technique_id:
            technique = db.get_technique(args.technique_id)
            techniques = [technique] if technique else []
        else:
            techniques = db.get_all_techniques()
        
        if not techniques:
            logger.error("No techniques found to process")
            sys.exit(1)
        
        # Generate signatures
        for technique in techniques:
            logger.info(f"Processing technique {technique.technique_id}")
            
            for sig_type, converter in converters.items():
                try:
                    signature = converter.convert(technique)
                    if signature:
                        # Save signature to database
                        sig_data = {
                            'technique_id': technique.id,
                            'signature_type': sig_type,
                            'content': signature,
                            'metadata': {
                                'generated_at': str(datetime.now(UTC)),
                                'converter_version': converter.VERSION
                            }
                        }
                        db.add_signature(sig_data)
                        
                        # Save signature to file
                        file_path = output_dir / sig_type / f"{technique.technique_id}.{sig_type}"
                        with open(file_path, 'w') as f:
                            f.write(signature)
                        
                        logger.info(f"Generated {sig_type} signature for {technique.technique_id}")
                    else:
                        logger.warning(f"No {sig_type} signature generated for {technique.technique_id}")
                        
                except Exception as e:
                    logger.error(f"Error generating {sig_type} signature for {technique.technique_id}: {str(e)}")
        
        logger.info("Signature generation completed")
        
    except Exception as e:
        logger.error(f"Error generating signatures: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 