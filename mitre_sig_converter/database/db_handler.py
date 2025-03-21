"""
Database handler for storing MITRE ATT&CK techniques and signatures.
"""

import sqlite3
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.utils.logger import get_logger
from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.api.mitre_api import MitreMatrix

logger = get_logger(__name__)

class DatabaseHandler:
    """Class for handling database operations."""
    
    def __init__(self):
        """Initialize the database handler."""
        self.config = ConfigHandler()
        self.db_file = self.config.get('DATABASE', 'db_file')
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema."""
        try:
            # Create database directory if it doesn't exist
            db_dir = Path(self.db_file).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Create techniques table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS techniques (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        tactics TEXT,
                        platforms TEXT,
                        data_sources TEXT,
                        detection TEXT,
                        related_techniques TEXT,
                        is_subtechnique BOOLEAN,
                        matrix TEXT NOT NULL,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technique_id TEXT NOT NULL,
                        format TEXT NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (technique_id) REFERENCES techniques (id),
                        UNIQUE (technique_id, format)
                    )
                """)
                
                # Create index on technique_id and matrix
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_techniques_matrix 
                    ON techniques (matrix)
                """)
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def update_techniques(self, techniques: List[Technique]):
        """
        Update the database with a list of techniques.
        
        Args:
            techniques: List of techniques to update
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                for technique in techniques:
                    cursor.execute("""
                        INSERT OR REPLACE INTO techniques (
                            id, name, description, tactics, platforms,
                            data_sources, detection, related_techniques,
                            is_subtechnique, matrix, last_updated
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        technique.id,
                        technique.name,
                        technique.description,
                        json.dumps(technique.tactics),
                        json.dumps(technique.platforms),
                        json.dumps(technique.data_sources),
                        technique.detection,
                        json.dumps(technique.related_techniques),
                        technique.is_subtechnique,
                        technique.matrix
                    ))
                
                conn.commit()
                logger.info(f"Updated {len(techniques)} techniques in database")
                
        except Exception as e:
            logger.error(f"Error updating techniques: {e}")
            raise
    
    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """
        Get a technique by ID.
        
        Args:
            technique_id: The technique ID to retrieve
            
        Returns:
            The technique if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM techniques WHERE id = ?
                """, (technique_id,))
                
                row = cursor.fetchone()
                if row:
                    return self._row_to_technique(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting technique {technique_id}: {e}")
            return None
    
    def get_techniques_by_matrix(self, matrix: MitreMatrix) -> List[Technique]:
        """
        Get all techniques for a specific matrix.
        
        Args:
            matrix: The MITRE ATT&CK matrix to get techniques for
            
        Returns:
            List of techniques for the specified matrix
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM techniques WHERE matrix = ?
                """, (matrix.value,))
                
                return [self._row_to_technique(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting techniques for matrix {matrix.value}: {e}")
            return []
    
    def get_techniques_by_tactic(self, tactic: str, matrix: MitreMatrix) -> List[Technique]:
        """
        Get techniques for a specific tactic and matrix.
        
        Args:
            tactic: The tactic to get techniques for
            matrix: The MITRE ATT&CK matrix to get techniques for
            
        Returns:
            List of techniques for the specified tactic and matrix
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM techniques 
                    WHERE matrix = ? AND json_array_length(tactics) > 0
                """, (matrix.value,))
                
                techniques = []
                for row in cursor.fetchall():
                    technique = self._row_to_technique(row)
                    if tactic in technique.tactics:
                        techniques.append(technique)
                
                return techniques
                
        except Exception as e:
            logger.error(f"Error getting techniques for tactic {tactic}: {e}")
            return []
    
    def save_signature(self, technique_id: str, format: str, content: str):
        """
        Save a signature for a technique.
        
        Args:
            technique_id: The technique ID
            format: The signature format (yara, sigma, kql)
            content: The signature content
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO signatures (
                        technique_id, format, content, created_at
                    ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (technique_id, format, content))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error saving signature for technique {technique_id}: {e}")
            raise
    
    def get_signature(self, technique_id: str, format: str) -> Optional[str]:
        """
        Get a signature for a technique.
        
        Args:
            technique_id: The technique ID
            format: The signature format (yara, sigma, kql)
            
        Returns:
            The signature content if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT content FROM signatures 
                    WHERE technique_id = ? AND format = ?
                """, (technique_id, format))
                
                row = cursor.fetchone()
                return row[0] if row else None
                
        except Exception as e:
            logger.error(f"Error getting signature for technique {technique_id}: {e}")
            return None
    
    def get_all_signatures(self, format: str) -> List[Dict[str, str]]:
        """
        Get all signatures of a specific format.
        
        Args:
            format: The signature format (yara, sigma, kql)
            
        Returns:
            List of dictionaries containing technique_id and content
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT technique_id, content FROM signatures 
                    WHERE format = ?
                """, (format,))
                
                return [
                    {"technique_id": row[0], "content": row[1]}
                    for row in cursor.fetchall()
                ]
                
        except Exception as e:
            logger.error(f"Error getting all signatures for format {format}: {e}")
            return []
    
    def _row_to_technique(self, row: tuple) -> Technique:
        """
        Convert a database row to a Technique object.
        
        Args:
            row: The database row to convert
            
        Returns:
            A Technique object
        """
        return Technique(
            id=row[0],
            name=row[1],
            description=row[2],
            tactics=json.loads(row[3]),
            platforms=json.loads(row[4]),
            data_sources=json.loads(row[5]),
            detection=row[6],
            related_techniques=json.loads(row[7]),
            is_subtechnique=bool(row[8]),
            matrix=row[9]
        )
