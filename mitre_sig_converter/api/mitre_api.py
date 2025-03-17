"""
Module for interacting with MITRE ATT&CK data.
"""

import json
import os
import datetime
from typing import List, Dict, Any, Optional

from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.utils.logger import get_logger
from mitre_sig_converter.models.technique import Technique

logger = get_logger(__name__)

class MitreApi:
    """Class for interfacing with MITRE ATT&CK data."""

    def __init__(self):
        """Initialize the MITRE API handler."""
        self.config = ConfigHandler()
        self.enterprise_file = self.config.get('MITRE', 'enterprise_file')
        self.enterprise_data = self._load_enterprise_data()
        self.techniques = self._parse_techniques()
        self.tactics = self._parse_tactics()
        
    def _load_enterprise_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK Enterprise data from file."""
        try:
            if not os.path.exists(self.enterprise_file):
                logger.error(f"MITRE ATT&CK data file not found: {self.enterprise_file}")
                logger.info("Run 'scripts/download_mitre.py' to download the data")
                return {}
            
            with open(self.enterprise_file, 'r', encoding='utf-8') as f:
                return json.load(f)
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
                technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                
                if not technique_id or not technique_id.startswith('T'):
                    continue
                
                # Get tactics (kill chain phases)
                kill_chain_phases = obj.get('kill_chain_phases', [])
                tactics = [phase.get('phase_name') for phase in kill_chain_phases 
                           if phase.get('kill_chain_name') == 'mitre-attack']
                
                # Get data sources
                data_sources = []
                if 'x_mitre_data_sources' in obj:
                    data_sources = obj['x_mitre_data_sources']
                elif 'x_mitre_detection' in obj:
                    # Older MITRE format might have detection information
                    data_sources = [obj['x_mitre_detection']]
                
                # Get platforms
                platforms = obj.get('x_mitre_platforms', [])
                
                # Get related techniques (sub-techniques or parent techniques)
                related_techniques = []
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack' and ref.get('external_id', '') != technique_id:
                        related_techniques.append(ref.get('external_id'))
                
                techniques[technique_id] = Technique(
                    id=technique_id,
                    name=obj.get('name', ''),
                    description=obj.get('description', ''),
                    tactics=tactics,
                    platforms=platforms,
                    data_sources=data_sources,
                    detection=obj.get('x_mitre_detection', ''),
                    related_techniques=related_techniques,
                    is_subtechnique='.' in technique_id
                )
        
        return techniques
    
    def _parse_tactics(self) -> Dict[str, List[str]]:
        """Parse tactics and associate techniques with them."""
        tactics = {}
        
        for technique_id, technique in self.techniques.items():
            for tactic in technique.tactics:
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(technique_id)
        
        return tactics
    
    def get_all_techniques(self) -> List[Technique]:
        """Get all techniques."""
        return list(self.techniques.values())
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Technique]:
        """Get a technique by its ID."""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Technique]:
        """Get techniques associated with a specific tactic."""
        # Try to normalize tactic name (e.g., convert "defense-evasion" to "defense-evasion")
        normalized_tactic = tactic.lower().replace(' ', '-')
        
        # Find matching tactic
        matching_tactic = None
        for t in self.tactics.keys():
            if t.lower() == normalized_tactic:
                matching_tactic = t
                break
        
        if not matching_tactic:
            return []
        
        technique_ids = self.tactics.get(matching_tactic, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def get_subtechniques(self, parent_id: str) -> List[Technique]:
        """Get sub-techniques for a parent technique."""
        return [t for t in self.techniques.values() 
                if t.is_subtechnique and t.id.startswith(parent_id + '.')]
    
    def get_parent_technique(self, subtechnique_id: str) -> Optional[Technique]:
        """Get the parent technique for a sub-technique."""
        if '.' not in subtechnique_id:
            return None
        
        parent_id = subtechnique_id.split('.')[0]
        return self.get_technique_by_id(parent_id)
