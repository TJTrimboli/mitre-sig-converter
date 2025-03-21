"""
Module for interacting with MITRE ATT&CK data.
"""

import json
import os
import datetime
from typing import List, Dict, Any, Optional, Union
from enum import Enum

from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.utils.logger import get_logger
from mitre_sig_converter.models.technique import Technique

logger = get_logger(__name__)

class MitreMatrix(Enum):
    """Enumeration of MITRE ATT&CK matrices."""
    ENTERPRISE = "enterprise"
    MOBILE = "mobile"
    ICS = "ics"

class MitreApi:
    """Class for interfacing with MITRE ATT&CK data."""

    def __init__(self, matrix: Union[MitreMatrix, str] = MitreMatrix.ENTERPRISE, config_handler: Optional[ConfigHandler] = None):
        """
        Initialize the MITRE API handler.
        
        Args:
            matrix: The MITRE ATT&CK matrix to use (default: Enterprise)
            config_handler: Optional ConfigHandler instance to use (default: None)

        Raises:
            ValueError: If matrix is not a valid MitreMatrix value.
        """
        self.config = config_handler or ConfigHandler()
        if isinstance(matrix, str):
            try:
                self.matrix = MitreMatrix(matrix)
            except ValueError:
                raise ValueError(f"Invalid matrix: {matrix}")
        else:
            self.matrix = matrix

        # Get the data file path from config
        file_key = f'MITRE.{self.matrix.value}_file'
        self.data_file = self.config.get(file_key)
        if not self.data_file:
            logger.error(f"MITRE ATT&CK data file not found: {file_key}")
            logger.info("Run 'scripts/download_mitre.py' to download the data")
            self.data_file = None
        
        # Print the data file path for debugging
        print(f"\nData file path: {self.data_file}")
        
        self.enterprise_data = self._load_enterprise_data()
        self.techniques = self._parse_techniques()
        self.tactics = self._parse_tactics()
        
    def _load_enterprise_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK data from file."""
        try:
            if not self.data_file:
                return {}
            
            with open(self.data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data
        except Exception as e:
            logger.exception(f"Error loading MITRE ATT&CK data: {e}")
            return {}
    
    def _parse_techniques(self) -> Dict[str, Technique]:
        """Parse technique objects from MITRE data."""
        techniques = {}
        
        if not self.enterprise_data:
            return techniques
        
        for obj in self.enterprise_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                # Get technique ID
                external_refs = obj.get('external_references', [])
                technique_id = None
                for ref in external_refs:
                    if ref.get('source_name') == f'mitre-{self.matrix.value}':
                        technique_id = ref.get('external_id')
                        break
                
                if not technique_id or not technique_id.startswith('T'):
                    continue
                
                # Get tactics (kill chain phases)
                kill_chain_phases = obj.get('kill_chain_phases', [])
                tactics = [phase.get('phase_name') for phase in kill_chain_phases 
                          if phase.get('kill_chain_name') == f'mitre-{self.matrix.value}']
                
                # Get data sources
                data_sources = []
                if 'x_mitre_data_sources' in obj:
                    data_sources = obj['x_mitre_data_sources']
                elif 'x_mitre_detection' in obj:
                    data_sources = [obj['x_mitre_detection']]
                
                # Get platforms
                platforms = obj.get('x_mitre_platforms', [])
                
                # Get related techniques (sub-techniques or parent techniques)
                related_techniques = []
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == f'mitre-{self.matrix.value}' and ref.get('external_id', '') != technique_id:
                        related_techniques.append(ref.get('external_id'))
                
                # Create technique object
                technique = Technique(
                    id=technique_id,
                    name=obj.get('name', ''),
                    description=obj.get('description', ''),
                    tactics=tactics,
                    platforms=platforms,
                    data_sources=data_sources,
                    detection=obj.get('x_mitre_detection', ''),
                    related_techniques=related_techniques,
                    is_subtechnique='.' in technique_id,
                    matrix=self.matrix.value
                )
                
                techniques[technique_id] = technique
        
        return techniques
    
    def _parse_tactics(self) -> Dict[str, List[str]]:
        """Parse tactic objects from MITRE data."""
        tactics = {}
        
        if not self.enterprise_data:
            return tactics
        
        # First try to get tactics from x-mitre-tactic objects
        for obj in self.enterprise_data.get('objects', []):
            if obj.get('type') == 'x-mitre-tactic':
                tactic_name = obj.get('name', '').lower()
                if not tactic_name:
                    continue
                
                # Get techniques for this tactic
                techniques = []
                for technique in self.techniques.values():
                    if tactic_name in technique.tactics:
                        techniques.append(technique.id)
                
                tactics[tactic_name] = techniques
        
        # If no tactics were found, extract them from technique objects
        if not tactics:
            # Build a mapping of tactics to techniques
            for technique in self.techniques.values():
                for tactic in technique.tactics:
                    if tactic not in tactics:
                        tactics[tactic] = []
                    tactics[tactic].append(technique.id)
        
        return tactics
    
    def get_all_techniques(self) -> List[Technique]:
        """Get all techniques for the current matrix."""
        return list(self.techniques.values())
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Technique]:
        """Get a technique by its ID."""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Technique]:
        """Get all techniques for a specific tactic."""
        tactic = tactic.lower()
        technique_ids = self.tactics.get(tactic, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def get_subtechniques(self, parent_id: str) -> List[Technique]:
        """Get all sub-techniques for a parent technique."""
        return [t for t in self.techniques.values() if t.is_subtechnique and t.parent_technique_id == parent_id]
    
    def get_parent_technique(self, subtechnique_id: str) -> Optional[Technique]:
        """Get the parent technique for a sub-technique."""
        technique = self.techniques.get(subtechnique_id)
        if not technique or not technique.is_subtechnique:
            return None
        return self.techniques.get(technique.parent_technique_id)
