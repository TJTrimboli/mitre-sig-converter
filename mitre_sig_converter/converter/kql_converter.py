"""
KQL query converter for MITRE ATT&CK techniques.
"""
import os
import re
from typing import Dict, Any, List, Optional

from mitre_sig_converter.converter.base_converter import BaseConverter
from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.utils.logger import get_logger

logger = get_logger(__name__)

class KqlConverter(BaseConverter):
    """Converter for generating KQL queries from MITRE ATT&CK techniques."""
    
    def __init__(self):
        """Initialize the KQL converter."""
        template_path = os.path.join(
            os.path.dirname(__file__), 
            'templates', 
            'kql_template.j2'
        )
        super().__init__(template_path)
    
    def convert(self, technique: Technique) -> str:
        """
        Convert a MITRE ATT&CK technique to a KQL query.
        
        Args:
            technique: The technique to convert.
            
        Returns:
            str: KQL query text.
        """
        context = self.create_signature_context(technique)
        
        # Add KQL-specific context
        context.update({
            'query_id': f"MITRE_ATT_CK_{technique.id.replace('.', '_')}",
            'tables': self._determine_tables(technique),
            'query_parts': self._generate_query_parts(technique),
            'author': "MITRE ATT&CK Signature Converter",
            'reference': f"https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}/"
        })
        
        return self._render_template('kql_template.j2', context)
    
    def _determine_tables(self, technique: Technique) -> List[str]:
        """
        Determine which tables to query based on the technique.
        
        Args:
            technique: The technique to determine tables for.
            
        Returns:
            List[str]: List of table names.
        """
        tables = []
        
        # Define common tables for different platforms
        if any(p.lower() == 'windows' for p in technique.platforms):
            # Windows-specific tables
            if technique.id.startswith('T1055'):  # Process Injection
                tables.extend(['SecurityEvent', 'WindowsEvent', 'SecurityAlert'])
            elif technique.id.startswith('T1059'):  # Command and Scripting Interpreter
                tables.extend(['SecurityEvent', 'WindowsEvent', 'ProcessEvents'])
            elif technique.id.startswith('T1547'):  # Boot or Logon Autostart Execution
                tables.extend(['SecurityEvent', 'WindowsEvent', 'RegistryEvents'])
            elif technique.id.startswith('T1078'):  # Valid Accounts
                tables.extend(['SecurityEvent', 'SigninLogs', 'AuditLogs'])
            elif technique.id.startswith('T1071'):  # Application Layer Protocol
                tables.extend(['NetworkEvents', 'DnsEvents', 'CommonSecurityLog'])
        
        if any(p.lower() == 'linux' for p in technique.platforms):
            # Linux-specific tables
            if technique.id.startswith('T1059'):  # Command and Scripting Interpreter
                tables.extend(['Syslog', 'LinuxAuditLogs'])
            elif technique.id.startswith('T1547'):  # Boot or Logon Autostart Execution
                tables.extend(['Syslog', 'LinuxAuditLogs'])
            elif technique.id.startswith('T1078'):  # Valid Accounts
                tables.extend(['Syslog', 'LinuxAuditLogs'])
            elif technique.id.startswith('T1071'):  # Application Layer Protocol
                tables.extend(['NetworkEvents', 'DnsEvents'])
        
        if any(p.lower() == 'macos' for p in technique.platforms):
            # macOS-specific tables
            if technique.id.startswith('T1059'):  # Command and Scripting Interpreter
                tables.extend(['MacOSAuditLogs', 'Syslog'])
            elif technique.id.startswith('T1547'):  # Boot or Logon Autostart Execution
                tables.extend(['MacOSAuditLogs', 'Syslog'])
            elif technique.id.startswith('T1078'):  # Valid Accounts
                tables.extend(['MacOSAuditLogs', 'Syslog'])
        
        # Add environment-agnostic tables
        tables.extend(['SecurityAlert', 'SecurityIncident'])
        
        # Remove duplicates
        tables = list(dict.fromkeys(tables))
        
        return tables
    
    def _generate_query_parts(self, technique: Technique) -> List[Dict[str, str]]:
        """
        Generate KQL query parts for the technique.
        
        Args:
            technique: The technique to generate query parts for.
            
        Returns:
            List[Dict[str, str]]: List of query parts.
        """
        query_parts = []
        
        # Process common processes
        if technique.get_common_processes():
            processes = technique.get_common_processes()
            process_clause = " or ".join([f"Process contains \"{p}\"" for p in processes])
            query_parts.append({
                'table': 'ProcessEvents',
                'where': f"({process_clause})"
            })
        
        # Process common files
        if technique.get_common_files():
            files = technique.get_common_files()
            file_clause = " or ".join([f"TargetFilename contains \"{f}\"" for f in files])
            query_parts.append({
                'table': 'FileEvents',
                'where': f"({file_clause})"
            })
        
        # Process registry keys
        if technique.get_common_registry_keys():
            registry_keys = technique.get_common_registry_keys()
            registry_clause = " or ".join([f"RegistryKey contains \"{r}\"" for r in registry_keys])
            query_parts.append({
                'table': 'RegistryEvents',
                'where': f"({registry_clause})"
            })
        
        # Process network indicators
        if technique.get_common_network_indicators():
            network_indicators = technique.get_common_network_indicators()
            
            # DNS-related
            if any("DNS" in indicator for indicator in network_indicators):
                query_parts.append({
                    'table': 'DnsEvents',
                    'where': "isnotempty(QueryName)"
                })
            
            # HTTP-related
            if any("HTTP" in indicator for indicator in network_indicators):
                query_parts.append({
                    'table': 'NetworkEvents',
                    'where': "RemotePort in (80,