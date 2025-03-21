#!/usr/bin/env python3
from mitre_sig_converter.api import MitreApi
from mitre_sig_converter.utils import setup_logger, FileHandler
from pathlib import Path
import argparse
import sys
import json
from datetime import datetime, UTC
import os
import requests
from typing import Dict, Any, List

from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.api.mitre_api import MitreMatrix

logger = get_logger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Download and cache MITRE ATT&CK data')
    parser.add_argument('--output-dir', type=str, default='data/mitre',
                       help='Output directory for MITRE data (default: data/mitre)')
    parser.add_argument('--log-file', type=str, default='logs/download_mitre.log',
                       help='Log file path (default: logs/download_mitre.log)')
    return parser.parse_args()

class MitreDownloader:
    """Class for downloading and caching MITRE ATT&CK data."""
    
    def __init__(self):
        """Initialize the MITRE downloader."""
        self.config = ConfigHandler()
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.matrices = {
            MitreMatrix.ENTERPRISE: "enterprise-attack",
            MitreMatrix.MOBILE: "mobile-attack",
            MitreMatrix.ICS: "ics-attack"
        }
    
    def download_matrix(self, matrix: MitreMatrix) -> Dict[str, Any]:
        """
        Download MITRE ATT&CK data for a specific matrix.
        
        Args:
            matrix: The MITRE ATT&CK matrix to download
            
        Returns:
            Dictionary containing the downloaded data
        """
        matrix_name = self.matrices[matrix]
        url = f"{self.base_url}/{matrix_name}/{matrix_name}.json"
        
        try:
            logger.info(f"Downloading {matrix_name} data from {url}")
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading {matrix_name} data: {e}")
            return {}
    
    def save_matrix_data(self, matrix: MitreMatrix, data: Dict[str, Any]) -> bool:
        """
        Save downloaded matrix data to file.
        
        Args:
            matrix: The MITRE ATT&CK matrix
            data: The data to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_file = self.config.get('MITRE', f'{matrix.value}_file')
            output_dir = os.path.dirname(output_file)
            
            # Create output directory if it doesn't exist
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            # Save the data
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {matrix.value} data to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving {matrix.value} data: {e}")
            return False
    
    def save_metadata(self, matrix: MitreMatrix, data: Dict[str, Any]) -> bool:
        """
        Save metadata about the downloaded data.
        
        Args:
            matrix: The MITRE ATT&CK matrix
            data: The downloaded data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            metadata_file = self.config.get('MITRE', f'{matrix.value}_metadata')
            metadata_dir = os.path.dirname(metadata_file)
            
            # Create metadata directory if it doesn't exist
            if metadata_dir:
                os.makedirs(metadata_dir, exist_ok=True)
            
            # Extract metadata
            metadata = {
                'download_date': datetime.now().isoformat(),
                'matrix': matrix.value,
                'version': data.get('version', 'unknown'),
                'technique_count': len([obj for obj in data.get('objects', []) 
                                     if obj.get('type') == 'attack-pattern']),
                'tactic_count': len([obj for obj in data.get('objects', []) 
                                   if obj.get('type') == 'x-mitre-tactic'])
            }
            
            # Save the metadata
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Saved {matrix.value} metadata to {metadata_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving {matrix.value} metadata: {e}")
            return False
    
    def download_all_matrices(self) -> bool:
        """
        Download and cache data for all MITRE ATT&CK matrices.
        
        Returns:
            True if successful, False otherwise
        """
        success = True
        
        for matrix in MitreMatrix:
            # Download the data
            data = self.download_matrix(matrix)
            if not data:
                success = False
                continue
            
            # Save the data
            if not self.save_matrix_data(matrix, data):
                success = False
                continue
            
            # Save metadata
            if not self.save_metadata(matrix, data):
                success = False
                continue
        
        return success

def main():
    """Main entry point for the script."""
    downloader = MitreDownloader()
    
    if downloader.download_all_matrices():
        logger.info("Successfully downloaded and cached all MITRE ATT&CK data")
    else:
        logger.error("Failed to download or cache some MITRE ATT&CK data")
        exit(1)

if __name__ == '__main__':
    main()
