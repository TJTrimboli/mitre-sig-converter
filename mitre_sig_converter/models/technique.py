"""
Module containing model definitions for MITRE ATT&CK techniques.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

class MitreMatrix(Enum):
    """Enumeration of MITRE ATT&CK matrices."""
    ENTERPRISE = "enterprise"
    MOBILE = "mobile"
    ICS = "ics"

@dataclass
class Technique:
    """Data class representing a MITRE ATT&CK technique or sub-technique."""
    
    id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection: str
    related_techniques: List[str]
    is_subtechnique: bool
    matrix: str = field(default=MitreMatrix.ENTERPRISE.value)
    
    def __post_init__(self):
        """Validate and normalize data after initialization."""
        # Ensure lists are not None
        self.tactics = self.tactics or []
        self.platforms = self.platforms or []
        self.data_sources = self.data_sources or []
        self.related_techniques = self.related_techniques or []
        
        # Normalize strings
        self.id = str(self.id).strip()
        self.name = str(self.name).strip()
        self.description = str(self.description).strip()
        self.detection = str(self.detection).strip()
        
        # Validate matrix
        if self.matrix not in [m.value for m in MitreMatrix]:
            raise ValueError(f"Invalid matrix: {self.matrix}")
    
    def get_detection_patterns(self) -> List[str]:
        """
        Extract detection patterns from the technique's detection field.
        
        Returns:
            List of detection patterns found in the technique's detection field.
        """
        patterns = []
        if not self.detection:
            return patterns
            
        # Look for common pattern indicators
        indicators = [
            "process_name", "file_name", "command_line", "registry_key",
            "network_connection", "service_name", "dll_name", "module_name"
        ]
        
        for line in self.detection.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            for indicator in indicators:
                if indicator in line.lower():
                    patterns.append(line)
                    break
        
        return patterns
    
    def get_environment_agnostic_patterns(self) -> List[str]:
        """
        Extract environment-agnostic patterns from the technique's detection field.
        
        Returns:
            List of environment-agnostic patterns found in the technique's detection field.
        """
        patterns = []
        if not self.detection:
            return patterns
            
        # Look for environment-agnostic indicators
        indicators = [
            "command_line", "process_name", "service_name", "dll_name",
            "module_name", "network_connection"
        ]
        
        for line in self.detection.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            for indicator in indicators:
                if indicator in line.lower():
                    patterns.append(line)
                    break
        
        return patterns
    
    def is_applicable_to_platform(self, platform: str) -> bool:
        """
        Check if the technique is applicable to a specific platform.
        
        Args:
            platform: The platform to check (e.g., "Windows", "Linux", "macOS")
            
        Returns:
            True if the technique is applicable to the platform, False otherwise.
        """
        platform = platform.lower()
        return platform in [p.lower() for p in self.platforms]
    
    def get_common_processes(self) -> List[str]:
        """
        Extract common process names from the technique's detection field.
        
        Returns:
            List of common process names found in the technique's detection field.
        """
        processes = []
        if not self.detection:
            return processes
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if "process_name" in line:
                # Try to extract process name from the line
                parts = line.split('=')
                if len(parts) > 1:
                    process = parts[1].strip()
                    if process:
                        processes.append(process)
        
        return processes
    
    def get_common_files(self) -> List[str]:
        """
        Extract common file paths from the technique's detection field.
        
        Returns:
            List of common file paths found in the technique's detection field.
        """
        files = []
        if not self.detection:
            return files
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if "file_name" in line or "file_path" in line:
                # Try to extract file path from the line
                parts = line.split('=')
                if len(parts) > 1:
                    file_path = parts[1].strip()
                    if file_path:
                        files.append(file_path)
        
        return files
    
    def get_common_registry_keys(self) -> List[str]:
        """
        Extract common registry keys from the technique's detection field.
        
        Returns:
            List of common registry keys found in the technique's detection field.
        """
        registry_keys = []
        if not self.detection:
            return registry_keys
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if "registry_key" in line:
                # Try to extract registry key from the line
                parts = line.split('=')
                if len(parts) > 1:
                    key = parts[1].strip()
                    if key:
                        registry_keys.append(key)
        
        return registry_keys
    
    def get_common_network_indicators(self) -> List[str]:
        """
        Extract network indicators from the technique's detection field.
        
        Returns:
            List of network indicators found in the technique's detection field.
        """
        indicators = []
        if not self.detection:
            return indicators
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if any(x in line for x in ["ip_address", "domain", "url", "port"]):
                # Try to extract network indicator from the line
                parts = line.split('=')
                if len(parts) > 1:
                    indicator = parts[1].strip()
                    if indicator:
                        indicators.append(indicator)
        
        return indicators
    
    def get_common_commands(self) -> List[str]:
        """
        Extract common commands from the technique's detection field.
        
        Returns:
            List of common commands found in the technique's detection field.
        """
        commands = []
        if not self.detection:
            return commands
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if "command_line" in line or "command" in line:
                # Try to extract command from the line
                parts = line.split('=')
                if len(parts) > 1:
                    command = parts[1].strip()
                    if command:
                        commands.append(command)
        
        return commands
    
    def get_common_services(self) -> List[str]:
        """
        Extract common service names from the technique's detection field.
        
        Returns:
            List of common service names found in the technique's detection field.
        """
        services = []
        if not self.detection:
            return services
            
        for line in self.detection.split('\n'):
            line = line.strip().lower()
            if not line:
                continue
                
            if "service_name" in line or "service" in line:
                # Try to extract service name from the line
                parts = line.split('=')
                if len(parts) > 1:
                    service = parts[1].strip()
                    if service:
                        services.append(service)
        
        return services
    
    @property
    def parent_technique_id(self) -> Optional[str]:
        """
        Get the parent technique ID for a sub-technique.
        
        Returns:
            The parent technique ID if this is a sub-technique, None otherwise.
        """
        if self.is_subtechnique and '.' in self.id:
            return self.id.split('.')[0]
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the technique to a dictionary.
        
        Returns:
            Dictionary representation of the technique.
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tactics': self.tactics,
            'platforms': self.platforms,
            'data_sources': self.data_sources,
            'detection': self.detection,
            'related_techniques': self.related_techniques,
            'is_subtechnique': self.is_subtechnique,
            'matrix': self.matrix
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Technique':
        """
        Create a Technique instance from a dictionary.
        
        Args:
            data: Dictionary containing technique data
            
        Returns:
            Technique instance created from the dictionary
        """
        return cls(**data)
