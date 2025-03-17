"""
Model definitions for MITRE ATT&CK techniques.
"""
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class Technique:
    """Represents a MITRE ATT&CK technique or sub-technique."""
    
    id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection: str
    related_techniques: List[str]
    is_subtechnique: bool
    
    def get_detection_patterns(self) -> List[str]:
        """
        Extract detection patterns from technique description and detection fields.
        
        Returns:
            List[str]: A list of detection patterns for this technique.
        """
        patterns = []
        
        # Process direct detection statements
        if self.detection:
            # Split detection text into paragraphs and bullet points
            detection_parts = self.detection.split('\n')
            for part in detection_parts:
                # Skip empty parts
                if not part.strip():
                    continue
                
                # Clean up the part
                clean_part = part.strip('- *').strip()
                if clean_part:
                    patterns.append(clean_part)
        
        # Look for keywords in description that might indicate detection methods
        detection_keywords = ['monitor', 'detect', 'look for', 'observe', 'identify']
        desc_lines = self.description.split('\n')
        
        for line in desc_lines:
            for keyword in detection_keywords:
                if keyword in line.lower():
                    patterns.append(line.strip())
                    break
        
        # Look for data sources that might be used for detection
        if self.data_sources:
            for source in self.data_sources:
                patterns.append(f"Data Source: {source}")
        
        return patterns
    
    def is_applicable_to_platform(self, platform: str) -> bool:
        """
        Check if this technique is applicable to a specific platform.
        
        Args:
            platform: Platform to check (e.g., 'Windows', 'Linux', 'macOS')
            
        Returns:
            bool: True if the technique applies to the platform, False otherwise
        """
        if not self.platforms:  # If no platforms specified, assume applicable to all
            return True
        
        # Normalize platform name for case-insensitive comparison
        normalized_platform = platform.lower()
        normalized_platforms = [p.lower() for p in self.platforms]
        
        # Check for exact match or patterns
        if normalized_platform in normalized_platforms:
            return True
        
        # Check for generalizations (e.g., if 'windows' is specified and checking for 'windows server')
        for p in normalized_platforms:
            if p in normalized_platform:
                return True
        
        return False
    
    def get_common_processes(self) -> List[str]:
        """
        Get common processes associated with this technique for detection.
        
        Returns:
            List[str]: Common process names associated with the technique
        """
        common_processes = []
        
        # Windows processes
        windows_processes = {
            'T1055': ['explorer.exe', 'lsass.exe', 'services.exe', 'svchost.exe'],  # Process Injection
            'T1059': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'],  # Command and Scripting Interpreter
            'T1053': ['schtasks.exe', 'at.exe'],  # Scheduled Task/Job
            'T1218': ['regsvr32.exe', 'rundll32.exe', 'msiexec.exe'],  # System Binary Proxy Execution
        }
        
        # Linux/macOS processes
        unix_processes = {
            'T1059': ['bash', 'sh', 'python', 'perl', 'ruby'],  # Command and Scripting Interpreter
            'T1053': ['cron', 'at'],  # Scheduled Task/Job
            'T1543': ['systemctl', 'launchctl', 'service'],  # Create or Modify System Process
        }
        
        # Add platform-specific processes
        if any(p.lower() in ['windows', 'win'] for p in self.platforms):
            base_id = self.id.split('.')[0]  # Get base technique ID
            if base_id in windows_processes:
                common_processes.extend(windows_processes[base_id])
                
        if any(p.lower() in ['linux', 'macos', 'mac os'] for p in self.platforms):
            base_id = self.id.split('.')[0]  # Get base technique ID
            if base_id in unix_processes:
                common_processes.extend(unix_processes[base_id])
        
        return common_processes
    
    def get_common_files(self) -> List[str]:
        """
        Get common files associated with this technique for detection.
        
        Returns:
            List[str]: Common file paths or patterns associated with the technique
        """
        common_files = []
        
        # Add platform-specific file paths
        if any(p.lower() == 'windows' for p in self.platforms):
            if self.id.startswith('T1547'):  # Boot or Logon Autostart Execution
                common_files.extend([
                    'C:\\Windows\\System32\\Tasks\\*',
                    'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*',
                    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*'
                ])
            elif self.id.startswith('T1059'):  # Command and Scripting Interpreter
                common_files.extend([
                    '*.ps1', '*.bat', '*.cmd', '*.vbs', '*.js'
                ])
        
        if any(p.lower() in ['linux', 'macos'] for p in self.platforms):
            if self.id.startswith('T1547'):  # Boot or Logon Autostart Execution
                common_files.extend([
                    '/etc/init.d/*',
                    '/etc/crontab',
                    '/etc/cron.*/*',
                    '/Library/LaunchAgents/*',
                    '/Library/LaunchDaemons/*',
                    '~/.bash_profile',
                    '~/.bashrc'
                ])
        
        return common_files
    
    def get_common_registry_keys(self) -> List[str]:
        """
        Get common registry keys associated with this technique (Windows-specific).
        
        Returns:
            List[str]: Common registry keys or patterns associated with the technique
        """
        if not any(p.lower() == 'windows' for p in self.platforms):
            return []
            
        common_registry = []
        
        # Registry locations for common persistence techniques
        if self.id.startswith('T1547'):  # Boot or Logon Autostart Execution
            common_registry.extend([
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ])
        elif self.id.startswith('T1112'):  # Modify Registry
            common_registry.extend([
                'HKLM\\SYSTEM\\CurrentControlSet\\Services',
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify',
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell'
            ])
        
        return common_registry
    
    def get_common_network_indicators(self) -> List[str]:
        """
        Get common network indicators associated with this technique.
        
        Returns:
            List[str]: Network indicators that might help detect the technique
        """
        indicators = []
        
        # Add technique-specific network indicators
        if self.id.startswith('T1071'):  # Application Layer Protocol
            indicators.extend([
                'Unusual outbound connections to high ports',
                'DNS queries with high entropy or encoded data',
                'HTTP/HTTPS requests with suspicious user agents',
                'Beaconing patterns in network traffic'
            ])
        elif self.id.startswith('T1095'):  # Non-Application Layer Protocol
            indicators.extend([
                'Direct use of TCP/UDP sockets',
                'ICMP traffic with data',
'Raw IP packets with unusual formats',
                'Non-standard protocol usage'
            ])
        elif self.id.startswith('T1571'):  # Non-Standard Port
            indicators.extend([
                'Common protocols on non-standard ports',
                'Web traffic on ports other than 80/443',
                'Database traffic on non-standard ports'
            ])
        elif self.id.startswith('T1572'):  # Protocol Tunneling
            indicators.extend([
                'DNS tunneling patterns',
                'HTTP/HTTPS tunneling over unexpected ports',
                'Unusual data patterns in standard protocols'
            ])
        
        return indicators
    
    def get_environment_agnostic_patterns(self) -> List[str]:
        """
        Get detection patterns that are agnostic to the environment.
        
        Returns:
            List[str]: Environment-agnostic detection patterns
        """
        patterns = []
        
        # Generic patterns applicable across platforms
        if self.id.startswith('T1055'):  # Process Injection
            patterns.extend([
                'Unusual memory allocation patterns',
                'Process creating threads in another process',
                'Unexpected process handle operations'
            ])
        elif self.id.startswith('T1059'):  # Command and Scripting Interpreter
            patterns.extend([
                'Execution of script interpreters with suspicious arguments',
                'Encoded or obfuscated command line arguments',
                'Script execution from unusual locations'
            ])
        elif self.id.startswith('T1569'):  # System Services
            patterns.extend([
                'Service creation with unusual executable paths',
                'Service modifications with suspicious command lines',
                'Unexpected service starts or stops'
            ])
        elif self.id.startswith('T1078'):  # Valid Accounts
            patterns.extend([
                'Authentication from unusual locations',
                'Login attempts at unusual times',
                'Multiple failed login attempts followed by successful login',
                'Privileged account usage for routine tasks'
            ])
        
        return patterns
