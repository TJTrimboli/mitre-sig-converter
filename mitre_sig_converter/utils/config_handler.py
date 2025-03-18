import os
from pathlib import Path
from typing import Any, Dict, Optional
import logging
from .file_handler import FileHandler

class ConfigHandler:
    def __init__(self, config_dir: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.file_handler = FileHandler(config_dir)
        self.config: Dict[str, Any] = {}

    def load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Load configuration from a file.
        
        Args:
            config_file: Path to the configuration file
            
        Returns:
            Dict containing the configuration
        """
        try:
            if config_file.endswith('.json'):
                self.config = self.file_handler.read_json(config_file)
            elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                self.config = self.file_handler.read_yaml(config_file)
            else:
                raise ValueError(f"Unsupported config file format: {config_file}")
            
            return self.config
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_file}: {str(e)}")
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key: Configuration key (can be dot-separated for nested values)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value
        """
        try:
            value = self.config
            for k in key.split('.'):
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key: Configuration key (can be dot-separated for nested values)
            value: Value to set
        """
        keys = key.split('.')
        current = self.config
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        current[keys[-1]] = value

    def save_config(self, config_file: str) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            config_file: Path to save the configuration to
        """
        try:
            if config_file.endswith('.json'):
                self.file_handler.write_json(self.config, config_file)
            elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                self.file_handler.write_yaml(self.config, config_file)
            else:
                raise ValueError(f"Unsupported config file format: {config_file}")
        except Exception as e:
            self.logger.error(f"Failed to save config file {config_file}: {str(e)}")
            raise

    def get_env_var(self, key: str, env_key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value, falling back to an environment variable.
        
        Args:
            key: Configuration key
            env_key: Environment variable key (defaults to uppercase version of key)
            default: Default value if neither config nor env var exists
            
        Returns:
            Configuration value
        """
        value = self.get(key)
        if value is not None:
            return value
            
        env_key = env_key or key.upper()
        return os.getenv(env_key, default)

    def merge_config(self, other_config: Dict[str, Any]) -> None:
        """
        Merge another configuration dictionary into the current one.
        
        Args:
            other_config: Configuration dictionary to merge
        """
        def deep_update(d: Dict[str, Any], u: Dict[str, Any]) -> Dict[str, Any]:
            for k, v in u.items():
                if isinstance(v, dict):
                    d[k] = deep_update(d.get(k, {}), v)
                else:
                    d[k] = v
            return d

        self.config = deep_update(self.config, other_config)
