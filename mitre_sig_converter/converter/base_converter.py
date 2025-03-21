"""
Base converter module for generating signatures from MITRE ATT&CK techniques.
"""

import os
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import jinja2

from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.utils.logger import get_logger

logger = get_logger(__name__)

class BaseConverter(ABC):
    """Base class for signature converters."""
    
    def __init__(self, template_path: Optional[str] = None):
        """
        Initialize the converter.
        
        Args:
            template_path: Path to the Jinja2 template file. If None, derived classes should handle template loading.
        """
        self.config = ConfigHandler()
        self.template_path = template_path
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(os.path.dirname(template_path) if template_path else "."),
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.env.filters['format_string'] = self._format_string
        self.env.filters['sanitize_id'] = self._sanitize_id
        self.env.filters['to_regex'] = self._to_regex
    
    @abstractmethod
    def convert(self, technique: Technique) -> str:
        """
        Convert a MITRE ATT&CK technique to a signature.
        
        Args:
            technique: The technique to convert.
            
        Returns:
            str: The generated signature.
        """
        pass
    
    def _format_string(self, string: str) -> str:
        """Format a string for use in signatures."""
        # Remove multiple spaces and newlines
        string = re.sub(r'\s+', ' ', string)
        # Remove special characters
        string = re.sub(r'[^\w\s]', '', string)
        return string.strip()
    
    def _sanitize_id(self, id_string: str) -> str:
        """Sanitize an ID for use in signatures."""
        # Replace dots with underscores
        return id_string.replace('.', '_')
    
    def _to_regex(self, pattern: str) -> str:
        """Convert a glob pattern to a regex pattern."""
        # Escape special regex characters
        pattern = re.escape(pattern)
        # Convert glob patterns to regex patterns
        pattern = pattern.replace('\\*', '.*')
        pattern = pattern.replace('\\?', '.')
        return pattern
    
    def _get_template(self, template_name: str) -> jinja2.Template:
        """
        Get a Jinja2 template.
        
        Args:
            template_name: Name of the template file.
            
        Returns:
            jinja2.Template: The loaded template.
        """
        try:
            return self.env.get_template(os.path.basename(template_name))
        except jinja2.exceptions.TemplateNotFound:
            logger.error(f"Template not found: {template_name}")
            raise
    
    def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Render a template with the given context.
        
        Args:
            template_name: Name of the template file.
            context: Context variables for rendering.
            
        Returns:
            str: The rendered template.
        """
        template = self._get_template(template_name)
        return template.render(**context)
    
    def create_signature_context(self, technique: Technique) -> Dict[str, Any]:
        """
        Create a context dictionary for template rendering.
        
        Args:
            technique: The technique to create context for.
            
        Returns:
            Dict[str, Any]: Context dictionary for template rendering.

        Raises:
            ValueError: If technique is None.
        """
        if technique is None:
            raise ValueError("Technique cannot be None")

        # Base context with technique information
        context = {
            'technique': technique,
            'id': technique.id,
            'name': technique.name,
            'description': technique.description,
            'tactics': technique.tactics,
            'platforms': technique.platforms,
            'detection_patterns': technique.get_detection_patterns(),
            'environment_agnostic_patterns': technique.get_environment_agnostic_patterns(),
            'common_processes': technique.get_common_processes(),
            'common_files': technique.get_common_files(),
            'common_registry_keys': technique.get_common_registry_keys(),
            'network_indicators': technique.get_common_network_indicators(),
        }
        return context
