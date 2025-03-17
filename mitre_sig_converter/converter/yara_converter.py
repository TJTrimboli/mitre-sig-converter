"""
YARA signature converter for MITRE ATT&CK techniques.
"""
import os
import re
from typing import Dict, Any, List

from mitre_sig_converter.converter.base_converter import BaseConverter
from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.utils.logger import get_logger

logger = get_logger(__name__)

class YaraConverter(BaseConverter):
    """Converter for generating YARA rules from MITRE ATT&CK techniques."""
    
    def __init__(self):
        """Initialize the YARA converter."""
        template_path = os.path.join(
            os.path.dirname(__file__), 
            'templates', 
            'yara_template.j2'
        )
        super().__init__(template_path)
    
    def convert(self, technique: Technique) -> str:
        """
        Convert a MITRE ATT&CK technique to a YARA rule.
        
        Args:
            technique: The technique to convert.
            
        Returns:
            str: YARA rule text.
        """
        context = self.create_signature_context(technique)
        
        # Add YARA-specific context
        context.update({
            'rule_name': f"MITRE_ATT_CK_{technique.id.replace('.', '_')}",
            'strings': self._generate_strings(technique),
            'conditions': self._generate_conditions(technique),
            'author': "MITRE ATT&CK Signature Converter",
            'reference': f"https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}/"
        })
        
        return self._render_template('yara_template.j2', context)
    
    def _generate_strings(self, technique: Technique) -> List[Dict[str, str]]:
        """
        Generate YARA strings for the technique.
        
        Args:
            technique: The technique to generate strings for.
            
        Returns:
            List[Dict[str, str]]: List of string definitions.
        """
        strings = []
        
        # Process common files
        for idx, file_path in enumerate(technique.get_common_files()):
            strings.append({
                'id': f"file_{idx}",
                'type': 'text',
                'value': file_path
            })
        
        # Process common processes
        for idx, process in enumerate(technique.get_common_processes()):
            strings.append({
                'id': f"process_{idx}",
                'type': 'text',
                'value': process
            })
        
        # Process registry keys
        for idx, registry in enumerate(technique.get_common_registry_keys()):
            strings.append({
                'id': f"registry_{idx}",
                'type': 'text',
                'value': registry
            })
        
        # Process network indicators - create regex patterns
        for idx, indicator in enumerate(technique.get_common_network_indicators()):
            if "DNS" in indicator:
                strings.append({
                    'id': f"dns_{idx}",
                    'type': 'regex',
                    'value': r'(dns|domain|nslookup)'
                })
            elif "HTTP" in indicator:
                strings.append({
                    'id': f"http_{idx}",
                    'type': 'regex',
                    'value': r'(http|https|web)'
                })
            elif "port" in indicator.lower():
                strings.append({
                    'id': f"port_{idx}",
                    'type': 'regex',
                    'value': r'(port|connect|socket)'
                })
        
        # Create environment-agnostic strings
        for idx, pattern in enumerate(technique.get_environment_agnostic_patterns()):
            # Convert the pattern to a basic regex/string
            if "memory allocation" in pattern.lower():
                strings.append({
                    'id': f"memory_{idx}",
                    'type': 'regex',
                    'value': r'(VirtualAlloc|mmap|malloc)'
                })
            elif "script" in pattern.lower():
                strings.append({
                    'id': f"script_{idx}",
                    'type': 'regex',
                    'value': r'(powershell|cmd\.exe|bash|python|perl|sh)'
                })
            elif "service" in pattern.lower():
                strings.append({
                    'id': f"service_{idx}",
                    'type': 'regex',
                    'value': r'(service|daemon|systemctl|systemd)'
                })
            elif "account" in pattern.lower() or "login" in pattern.lower():
                strings.append({
                    'id': f"account_{idx}",
                    'type': 'regex',
                    'value': r'(login|account|user|credential)'
                })
        
        return strings
    
    def _generate_conditions(self, technique: Technique) -> List[str]:
        """
        Generate YARA conditions for the technique.
        
        Args:
            technique: The technique to generate conditions for.
            
        Returns:
            List[str]: List of condition statements.
        """
        conditions = []
        
        # Group strings by type
        file_strings = []
        process_strings = []
        registry_strings = []
        network_strings = []
        other_strings = []
        
        # Count string types
        for string in self._generate_strings(technique):
            if string['id'].startswith('file_'):
                file_strings.append(string['id'])
            elif string['id'].startswith('process_'):
                process_strings.append(string['id'])
            elif string['id'].startswith('registry_'):
                registry_strings.append(string['id'])
            elif any(string['id'].startswith(prefix) for prefix in ['dns_', 'http_', 'port_']):
                network_strings.append(string['id'])
            else:
                other_strings.append(string['id'])
        
        # Create conditions based on string types
        if file_strings:
            if len(file_strings) > 1:
                conditions.append(f"any of ({', '.join('$' + s for s in file_strings)})")
            else:
                conditions.append(f"${file_strings[0]}")
        
        if process_strings:
            if len(process_strings) > 1:
                conditions.append(f"any of ({', '.join('$' + s for s in process_strings)})")
            else:
                conditions.append(f"${process_strings[0]}")
        
        if registry_strings:
            if len(registry_strings) > 1:
                conditions.append(f"any of ({', '.join('$' + s for s in registry_strings)})")
            else:
                conditions.append(f"${registry_strings[0]}")
        
        if network_strings:
            if len(network_strings) > 1:
                conditions.append(f"any of ({', '.join('$' + s for s in network_strings)})")
            else:
                conditions.append(f"${network_strings[0]}")
        
        if other_strings:
            if len(other_strings) > 1:
                conditions.append(f"any of ({', '.join('$' + s for s in other_strings)})")
            else:
                conditions.append(f"${other_strings[0]}")
        
        # If no conditions, add a basic one
        if not conditions:
            conditions.append("filesize < 5MB")
        
        return conditions
