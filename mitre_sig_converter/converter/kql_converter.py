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
                    'where': "RemotePort in (80, 443, 8080) or NetworkProtocol contains \"HTTP\""
                })
            
            # Other network indicators
            network_clause = " or ".join([f"NetworkProtocol contains \"{n}\" or RequestURL contains \"{n}\"" 
                                        for n in network_indicators])
            query_parts.append({
                'table': 'NetworkEvents',
                'where': f"({network_clause})"
            })
        
        # Process command line indicators
        if technique.get_common_commands():
            commands = technique.get_common_commands()
            command_clause = " or ".join([f"CommandLine contains \"{self._escape_kql_string(c)}\"" for c in commands])
            query_parts.append({
                'table': 'ProcessEvents',
                'where': f"({command_clause})"
            })
        
        # Process service indicators
        if technique.get_common_services():
            services = technique.get_common_services()
            service_clause = " or ".join([f"ServiceName contains \"{s}\"" for s in services])
            query_parts.append({
                'table': 'WindowsEvent',
                'where': f"EventID == 7045 and ({service_clause})"
            })
        
        # If no specific indicators, create generic detection based on description
        if not query_parts and technique.description:
            keywords = self._extract_keywords_from_description(technique.description)
            if keywords:
                keyword_clause = " or ".join([f"(Event contains \"{k}\")" for k in keywords])
                query_parts.append({
                    'table': 'SecurityEvent',
                    'where': f"({keyword_clause})"
                })
        
        return query_parts
    
    def _escape_kql_string(self, input_str: str) -> str:
        """
        Escape special characters in KQL string.
        
        Args:
            input_str: The string to escape.
            
        Returns:
            str: Escaped string.
        """
        # Replace double quotes with escaped double quotes
        return input_str.replace('"', '\\"')
    
    def _extract_keywords_from_description(self, description: str) -> List[str]:
        """
        Extract relevant keywords from technique description.
        
        Args:
            description: The technique description.
            
        Returns:
            List[str]: List of keywords.
        """
        # Remove common words and punctuation
        common_words = ['the', 'and', 'a', 'to', 'of', 'in', 'for', 'is', 'on', 'that', 'by']
        words = re.findall(r'\b\w+\b', description.lower())
        keywords = [word for word in words if word not in common_words and len(word) > 3]
        
        # Get unique keywords and limit to most relevant ones
        unique_keywords = list(dict.fromkeys(keywords))
        return unique_keywords[:10]  # Limit to 10 keywords
    
    def create_signature_context(self, technique: Technique) -> Dict[str, Any]:
        """
        Create a context dictionary for the template rendering.
        
        Args:
            technique: The technique to create context for.
            
        Returns:
            Dict[str, Any]: Context dictionary.
        """
        context = {
            'technique_id': technique.id,
            'technique_name': technique.name,
            'description': technique.description,
            'platforms': technique.platforms,
            'data_sources': technique.data_sources,
            'is_subtechnique': technique.is_subtechnique,
            'parent_technique': technique.parent_technique_id if technique.parent_technique_id else None,
        }
        
        return context
    
    def generate_query_name(self, technique: Technique) -> str:
        """
        Generate a name for the KQL query.
        
        Args:
            technique: The technique to generate name for.
            
        Returns:
            str: Query name.
        """
        name = f"MITRE ATT&CK: {technique.name} ({technique.id})"
        if technique.is_subtechnique and technique.parent_technique_id:
            name = f"MITRE ATT&CK: {technique.name} - Subtechnique of {technique.parent_technique_id}"
        
        return name
    
    def build_full_query(self, technique: Technique) -> str:
        """
        Build a complete KQL query with union of tables and comments.
        
        Args:
            technique: The technique to build query for.
            
        Returns:
            str: Complete KQL query.
        """
        tables = self._determine_tables(technique)
        query_parts = self._generate_query_parts(technique)
        
        if not query_parts:
            return f"// No specific indicators available for {technique.id}: {technique.name}\n" + \
                   "// Consider manual review of the technique description and create custom queries."
        
        query_lines = [
            f"// MITRE ATT&CK Technique: {technique.id} - {technique.name}",
            f"// Description: {technique.description[:150]}..." if len(technique.description) > 150 else f"// Description: {technique.description}",
            f"// Platforms: {', '.join(technique.platforms)}",
            f"// Reference: https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}/",
            ""
        ]
        
        # Group query parts by table
        table_queries = {}
        for part in query_parts:
            table = part['table']
            if table not in table_queries:
                table_queries[table] = []
            table_queries[table].append(part['where'])
        
        # Build individual table queries
        individual_queries = []
        for table, conditions in table_queries.items():
            where_clause = " or ".join([f"({condition})" for condition in conditions])
            individual_queries.append(f"{table} | where {where_clause}")
        
        # Unite all queries
        if len(individual_queries) > 1:
            query_lines.append(" | union ".join(individual_queries))
        else:
            query_lines.append(individual_queries[0])
        
        # Add projections and other common operations
        query_lines.append("| project TimeGenerated, Source=SourceSystem, Computer, EventID, Activity, CommandLine, ParentProcessName, ProcessName, FileName, UserName")
        query_lines.append("| extend Technique = 'MITRE ATT&CK " + technique.id + ": " + technique.name + "'")
        query_lines.append("| sort by TimeGenerated desc")
        
        return "\n".join(query_lines)
