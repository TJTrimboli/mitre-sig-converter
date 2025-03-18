import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

class FileHandler:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.logger = logging.getLogger(__name__)

    def ensure_directory(self, directory: Union[str, Path]) -> Path:
        """Ensure a directory exists, create it if it doesn't."""
        dir_path = self.base_dir / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def read_json(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Read a JSON file and return its contents."""
        try:
            with open(self.base_dir / file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to read JSON file {file_path}: {str(e)}")
            raise

    def write_json(self, data: Dict[str, Any], file_path: Union[str, Path]) -> None:
        """Write data to a JSON file."""
        try:
            with open(self.base_dir / file_path, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self.logger.error(f"Failed to write JSON file {file_path}: {str(e)}")
            raise

    def read_yaml(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Read a YAML file and return its contents."""
        try:
            with open(self.base_dir / file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to read YAML file {file_path}: {str(e)}")
            raise

    def write_yaml(self, data: Dict[str, Any], file_path: Union[str, Path]) -> None:
        """Write data to a YAML file."""
        try:
            with open(self.base_dir / file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
        except Exception as e:
            self.logger.error(f"Failed to write YAML file {file_path}: {str(e)}")
            raise

    def read_text(self, file_path: Union[str, Path]) -> str:
        """Read a text file and return its contents."""
        try:
            with open(self.base_dir / file_path, 'r') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to read text file {file_path}: {str(e)}")
            raise

    def write_text(self, content: str, file_path: Union[str, Path]) -> None:
        """Write text content to a file."""
        try:
            with open(self.base_dir / file_path, 'w') as f:
                f.write(content)
        except Exception as e:
            self.logger.error(f"Failed to write text file {file_path}: {str(e)}")
            raise

    def list_files(self, directory: Union[str, Path], pattern: str = "*") -> List[Path]:
        """List files in a directory matching the given pattern."""
        try:
            return list((self.base_dir / directory).glob(pattern))
        except Exception as e:
            self.logger.error(f"Failed to list files in {directory}: {str(e)}")
            raise

    def delete_file(self, file_path: Union[str, Path]) -> bool:
        """Delete a file if it exists."""
        try:
            path = self.base_dir / file_path
            if path.exists():
                path.unlink()
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to delete file {file_path}: {str(e)}")
            return False
