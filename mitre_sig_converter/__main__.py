#!/usr/bin/env python3
"""
Main entry point for the MITRE ATT&CK Signature Converter.
"""

import argparse
import sys
from typing import List, Optional
from pathlib import Path

from mitre_sig_converter.api.mitre_api import MitreApi, MitreMatrix
from mitre_sig_converter.converter import YaraConverter, SigmaConverter, KqlConverter
from mitre_sig_converter.database import DatabaseHandler
from mitre_sig_converter.models import Technique
from mitre_sig_converter.utils.logger import get_logger
from mitre_sig_converter.utils.file_handler import FileHandler
from mitre_sig_converter.utils.config_handler import ConfigHandler

logger = get_logger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Signature Converter")
    
    # Matrix selection
    parser.add_argument(
        "--matrix",
        choices=["enterprise", "mobile", "ics"],
        default="enterprise",
        help="MITRE ATT&CK matrix to use (default: enterprise)"
    )
    
    # Input options
    parser.add_argument(
        "--technique-id",
        help="Specific MITRE ATT&CK technique ID to convert"
    )
    parser.add_argument(
        "--tactic",
        help="Convert all techniques for a specific tactic"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir",
        help="Directory to save generated signatures"
    )
    parser.add_argument(
        "--format",
        choices=["yara", "sigma", "kql", "all"],
        default="all",
        help="Output format for signatures (default: all)"
    )
    
    # Database options
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Update the local database with latest MITRE data"
    )
    
    # Other options
    parser.add_argument(
        "--list-techniques",
        action="store_true",
        help="List all available techniques"
    )
    parser.add_argument(
        "--list-tactics",
        action="store_true",
        help="List all available tactics"
    )
    
    return parser.parse_args()

def get_matrix_enum(matrix_str: str) -> MitreMatrix:
    """Convert matrix string to MitreMatrix enum."""
    matrix_map = {
        "enterprise": MitreMatrix.ENTERPRISE,
        "mobile": MitreMatrix.MOBILE,
        "ics": MitreMatrix.ICS
    }
    return matrix_map.get(matrix_str, MitreMatrix.ENTERPRISE)

def list_techniques(api: MitreApi, matrix: MitreMatrix):
    """List all available techniques."""
    techniques = api.get_all_techniques()
    print(f"\nAvailable techniques for {matrix.value} matrix:")
    print("-" * 80)
    for technique in techniques:
        print(f"{technique.id}: {technique.name}")
    print(f"\nTotal techniques: {len(techniques)}")

def list_tactics(api: MitreApi, matrix: MitreMatrix):
    """List all available tactics."""
    tactics = api.tactics.keys()
    print(f"\nAvailable tactics for {matrix.value} matrix:")
    print("-" * 80)
    for tactic in sorted(tactics):
        print(f"- {tactic}")
    print(f"\nTotal tactics: {len(tactics)}")

def convert_technique(
    technique: Technique,
    output_dir: Path,
    format: str,
    converters: dict
):
    """Convert a single technique to signatures."""
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Convert based on format
        if format in ["yara", "all"]:
            yara_sig = converters["yara"].convert(technique)
            if yara_sig:
                yara_file = output_dir / f"{technique.id}.yar"
                yara_file.write_text(yara_sig)
                logger.info(f"Generated YARA signature: {yara_file}")
        
        if format in ["sigma", "all"]:
            sigma_sig = converters["sigma"].convert(technique)
            if sigma_sig:
                sigma_file = output_dir / f"{technique.id}.yml"
                sigma_file.write_text(sigma_sig)
                logger.info(f"Generated Sigma signature: {sigma_file}")
        
        if format in ["kql", "all"]:
            kql_sig = converters["kql"].convert(technique)
            if kql_sig:
                kql_file = output_dir / f"{technique.id}.kql"
                kql_file.write_text(kql_sig)
                logger.info(f"Generated KQL signature: {kql_file}")
        
        return True
    except Exception as e:
        logger.error(f"Error converting technique {technique.id}: {e}")
        return False

def main():
    """Main entry point."""
    args = parse_args()
    config = ConfigHandler()
    
    # Set output directory
    output_dir = Path(args.output_dir or config.get('GENERAL', 'output_dir'))
    
    # Initialize components
    matrix = get_matrix_enum(args.matrix)
    api = MitreApi(matrix)
    db = DatabaseHandler()
    converters = {
        "yara": YaraConverter(),
        "sigma": SigmaConverter(),
        "kql": KqlConverter()
    }
    
    try:
        # Update database if requested
        if args.update_db:
            logger.info("Updating database with latest MITRE data...")
            db.update_techniques(api.get_all_techniques())
            logger.info("Database update complete")
        
        # List options
        if args.list_techniques:
            list_techniques(api, matrix)
            return
        
        if args.list_tactics:
            list_tactics(api, matrix)
            return
        
        # Convert techniques
        techniques: List[Technique] = []
        
        if args.technique_id:
            # Convert specific technique
            technique = api.get_technique_by_id(args.technique_id)
            if technique:
                techniques = [technique]
            else:
                logger.error(f"Technique {args.technique_id} not found")
                return
        
        elif args.tactic:
            # Convert techniques by tactic
            techniques = api.get_techniques_by_tactic(args.tactic)
            if not techniques:
                logger.error(f"No techniques found for tactic: {args.tactic}")
                return
        
        else:
            # Convert all techniques
            techniques = api.get_all_techniques()
        
        # Convert techniques
        success_count = 0
        for technique in techniques:
            if convert_technique(technique, output_dir, args.format, converters):
                success_count += 1
        
        logger.info(f"Successfully converted {success_count} of {len(techniques)} techniques")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
        