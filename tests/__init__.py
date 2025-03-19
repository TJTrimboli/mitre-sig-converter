"""
Test suite for MITRE ATT&CK Signature Converter.
"""

import pytest
from pathlib import Path
from mitre_sig_converter.models import Technique
from mitre_sig_converter.database import DatabaseHandler

@pytest.fixture
def sample_technique_data():
    """Fixture providing sample MITRE ATT&CK technique data."""
    return {
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Process injection is a method of executing arbitrary code...',
        'platforms': ['Windows', 'Linux'],
        'data_sources': ['Process monitoring', 'API monitoring'],
        'tactics': ['execution', 'defense-evasion'],
        'detection': 'Monitor for suspicious process creation and API calls'
    }

@pytest.fixture
def sample_technique(sample_technique_data):
    """Fixture providing a Technique model instance."""
    return Technique.from_dict(sample_technique_data)

@pytest.fixture
def test_db():
    """Fixture providing an in-memory database for testing."""
    db = DatabaseHandler('sqlite:///:memory:')
    db.init_db()
    return db

@pytest.fixture
def test_data_dir(tmp_path):
    """Fixture providing a temporary directory for test data."""
    data_dir = tmp_path / 'test_data'
    data_dir.mkdir()
    return data_dir

@pytest.fixture
def test_log_dir(tmp_path):
    """Fixture providing a temporary directory for test logs."""
    log_dir = tmp_path / 'test_logs'
    log_dir.mkdir()
    return log_dir
