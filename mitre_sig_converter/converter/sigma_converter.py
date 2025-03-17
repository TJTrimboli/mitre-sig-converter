"""
Sigma rule converter for MITRE ATT&CK techniques.
"""
import os
import re
from typing import Dict, Any, List, Optional

from mitre_sig_converter.converter.base_converter import BaseConverter
from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.utils.logger import get_logger

logger = get_logger(__name__)

class SigmaConverter(BaseConverter):
    """Converter for generating Sigma rules from MITRE ATT&CK techniques."""
    
    def __init__(self):
        """Initialize the Sigma converter."""
        template_path = os.path.join(
            os.path.dirname(__file__), 
            'templates', 
            'sigma_template.j2'
        )
        super().__init__(template_path)
    
    def convert(self, technique: Technique) -> str:
        """
        Convert a MITRE ATT&CK technique to a Sigma rule.
        
        Args:
            technique: The technique to convert.
            
        Returns:
            str: Sigma rule text.
        """
        context = self.create_signature_context(technique)
        
        # Add Sigma-specific context
        context.update({
            'rule_id': f"mitre_attack_{technique.id.replace('.', '_').lower()}",
            'title': f"MITRE ATT&CK: {technique.name} - {technique.id}",
            'detection': self._generate_detection(technique),
            'logsource': self._determine_logsource(technique),
            'falsepositives': self._generate_falsepositives(technique),
            'level': self._determine_level(technique),
            'status': "experimental",
            'author': "MITRE ATT&CK Signature Converter",
            'references': [f"https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}"],
            'tags': self._generate_tags(technique)
        })
        
        return self._render_template('sigma_template.j2', context)
    
    def _generate_detection(self, technique: Technique) -> Dict[str, Any]:
        """
        Generate Sigma detection section.
        
        Args:
            technique: The technique to generate detection for.
            
        Returns:
            Dict[str, Any]: Detection section.
        """
        detection = {
            'selection': {},
            'condition': "selection"
        }
        
        # Process selection criteria based on technique type
        if technique.common_processes:
            # Process-based detection
            detection['selection'].update({
                'Image|endswith': technique.get_common_processes()
            })
        
        if technique.common_files:
            # File-based detection
            detection['selection'].update({
                'TargetFilename|endswith': technique.get_common_files()
            })
        
        if technique.common_registry_keys:
            # Registry-based detection
            detection['selection'].update({
                'TargetObject|contains': technique.get_common_registry_keys()
            })
        
        # Add environment-agnostic detection patterns
        agnostic_patterns = technique.get_environment_agnostic_patterns()
        if agnostic_patterns:
            # Convert patterns to Sigma-compatible format
            # For command-line arguments
            if any('command' in pattern.lower() for pattern in agnostic_patterns):
                detection['selection'].update({
                    'CommandLine|contains': [
                        p for p in agnostic_patterns 
                        if 'command' in p.lower() or 'argument' in p.lower()
                    ]
                })
            
            # For network-related patterns
            if any('network' in pattern.lower() or 'port' in pattern.lower() for pattern in agnostic_patterns):
                detection['selection'].update({
                    'DestinationPort': [
                        "!80", "!443", "!53", "!22", "!3389"  # Exclude common ports
                    ]
                })
            
            # For authentication-related patterns
            if any('login' in pattern.lower() or 'account' in pattern.lower() for pattern in agnostic_patterns):
                detection['selection'].update({
                    'EventID': ["4624", "4625", "4648", "4768", "4769", "4776"]
                })
                
                # Add another condition for non-Windows systems
                detection['selection_alt'] = {
                    'EventType': ["authentication", "login", "auth"]
                }
                detection['condition'] = "selection or selection_alt"
        
        # If no selection criteria determined, create a basic one based on technique name
        if not detection['selection']:
            # Look for keywords in technique name
            keywords = re.findall(r'\b\w+\b', technique.name.lower())
            significant_keywords = [k for k in keywords if len(k) > 3]
            
            if significant_keywords:
                detection['selection'] = {
                    'EventType|contains': significant_keywords
                }
        
        return detection
    
    def _determine_logsource(self, technique: Technique) -> Dict[str, str]:
        """
        Determine appropriate log source based on technique.
        
        Args:
            technique: The technique to determine log source for.
            
        Returns:
            Dict[str, str]: Log source configuration.
        """
        logsource = {}
        
        # Determine product based on platforms
        if any(p.lower() == 'windows' for p in technique.platforms):
            logsource['product'] = 'windows'
        elif any(p.lower() == 'linux' for p in technique.platforms):
            logsource['product'] = 'linux'
        elif any(p.lower() == 'macos' for p in technique.platforms):
            logsource['product'] = 'macos'
        else:
            # Generic product if no specific platform
            logsource['product'] = 'any'
        
        # Determine category based on technique type
        if technique.id.startswith('T1055'):  # Process Injection
            logsource['category'] = 'process_creation'
        elif technique.id.startswith('T1059'):  # Command and Scripting Interpreter
            logsource['category'] = 'process_creation'
        elif technique.id.startswith('T1547'):  # Boot or Logon Autostart Execution
            logsource['category'] = 'registry_event'
        elif technique.id.startswith('T1078'):  # Valid Accounts
            logsource['category'] = 'authentication'
        elif technique.id.startswith('T1071'):  # Application Layer Protocol
            logsource['category'] = 'network_connection'
        else:
            # Default to process creation for most techniques
            logsource['category'] = 'process_creation'
        
        # Make source more generic to be environment-agnostic
        if logsource['category'] == 'registry_event' and logsource['product'] != 'windows':
            logsource['category'] = 'file_event'
        
        return logsource
    
    def _generate_falsepositives(self, technique: Technique) -> List[str]:
        """
        Generate potential false positive scenarios.
        
        Args:
            technique: The technique to generate false positives for.
            
        Returns:
            List[str]: List of false positive scenarios.
        """
        falsepositives = ['Legitimate administrative activity']
        
        # Add technique-specific false positives
        if technique.id.startswith('T1059'):  # Command and Scripting Interpreter
            falsepositives.append('Legitimate scripting activity')
            falsepositives.append('System administration scripts')
        elif technique.id.startswith('T1055'):  # Process Injection
            falsepositives.append('Legitimate software with DLL injection')
            falsepositives.append('Antivirus software')
        elif technique.id.startswith('T1078'):  # Valid Accounts
            falsepositives.append('Legitimate user activity')
            falsepositives.append('Authorized administrative access')
        elif technique.id.startswith('T1071'):  # Application Layer Protocol
            falsepositives.append('Legitimate network traffic')
            falsepositives.append('Regular application communication')
        
        return falsepositives
    
    def _determine_level(self, technique: Technique) -> str:
        """
        Determine the alert level based on the technique.
        
        Args:
            technique: The technique to determine level for.
            
        Returns:
            str: Alert level.
        """
        # Determine level based on technique type
        if technique.id.startswith('T1055'):  # Process Injection
            return 'high'
        elif technique.id.startswith('T1059'):  # Command and Scripting Interpreter
            return 'medium'
        elif technique.id.startswith('T1078'):  # Valid Accounts
            return 'medium'
        elif technique.id.startswith('T1071'):  # Application Layer Protocol
            return 'low'
        else:
            # Default level
            return 'medium'
    
    def _generate_tags(self, technique: Technique) -> List[str]:
        """
        Generate tags for the Sigma rule.
        
        Args:
            technique: The technique to generate tags for.
            
        Returns:
            List[str]: List of tags.
        """
        tags = []
        
        # Add MITRE ATT&CK tags
        tags.append(f"attack.{technique.id}")
        
        # Add tactic tags
        for tactic in technique.tactics:
            tags.append(f"attack.tactic.{tactic}")
        
        # Add platform tags
        for platform in technique.platforms:
            tags.append(f"platform.{platform.lower()}")
        
        # Add environment-agnostic tag
        tags.append("mitre.environment.agnostic")
        
        return tags
