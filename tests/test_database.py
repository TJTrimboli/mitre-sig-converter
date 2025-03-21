"""
Tests for the database handler.
"""

import pytest
from pathlib import Path
import json
import sqlite3

from mitre_sig_converter.database.db_handler import DatabaseHandler
from mitre_sig_converter.models.technique import Technique
from mitre_sig_converter.api.mitre_api import MitreMatrix

@pytest.fixture
def sample_technique():
    """Create a sample technique for testing."""
    return Technique(
        id="T1234",
        name="Test Technique",
        description="Test description",
        tactics=["execution"],
        platforms=["Windows"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.ENTERPRISE.value
    )

@pytest.fixture
def test_db(tmp_path):
    """Create a temporary database for testing."""
    db_file = tmp_path / "test.db"
    handler = DatabaseHandler()
    handler.db_file = str(db_file)
    handler._init_db()
    return handler

def test_init_db(test_db):
    """Test database initialization."""
    with sqlite3.connect(test_db.db_file) as conn:
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('techniques', 'signatures')
        """)
        tables = cursor.fetchall()
        
        assert len(tables) == 2
        assert ("techniques",) in tables
        assert ("signatures",) in tables

def test_update_techniques(test_db, sample_technique):
    """Test updating techniques in the database."""
    test_db.update_techniques([sample_technique])
    
    # Verify technique was saved
    saved_technique = test_db.get_technique(sample_technique.id)
    assert saved_technique is not None
    assert saved_technique.id == sample_technique.id
    assert saved_technique.name == sample_technique.name
    assert saved_technique.matrix == sample_technique.matrix

def test_get_technique(test_db, sample_technique):
    """Test retrieving a technique by ID."""
    test_db.update_techniques([sample_technique])
    technique = test_db.get_technique(sample_technique.id)
    
    assert technique is not None
    assert technique.id == sample_technique.id
    assert technique.name == sample_technique.name
    assert technique.matrix == sample_technique.matrix

def test_get_techniques_by_matrix(test_db):
    """Test retrieving techniques by matrix."""
    # Create techniques for different matrices
    enterprise_tech = Technique(
        id="T1234",
        name="Enterprise Technique",
        description="Test description",
        tactics=["execution"],
        platforms=["Windows"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.ENTERPRISE.value
    )
    
    mobile_tech = Technique(
        id="T5678",
        name="Mobile Technique",
        description="Test description",
        tactics=["execution"],
        platforms=["Android"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.MOBILE.value
    )
    
    test_db.update_techniques([enterprise_tech, mobile_tech])
    
    # Test getting enterprise techniques
    enterprise_techniques = test_db.get_techniques_by_matrix(MitreMatrix.ENTERPRISE)
    assert len(enterprise_techniques) == 1
    assert enterprise_techniques[0].id == "T1234"
    assert enterprise_techniques[0].matrix == MitreMatrix.ENTERPRISE.value
    
    # Test getting mobile techniques
    mobile_techniques = test_db.get_techniques_by_matrix(MitreMatrix.MOBILE)
    assert len(mobile_techniques) == 1
    assert mobile_techniques[0].id == "T5678"
    assert mobile_techniques[0].matrix == MitreMatrix.MOBILE.value

def test_get_techniques_by_tactic(test_db):
    """Test retrieving techniques by tactic and matrix."""
    # Create techniques with different tactics
    execution_tech = Technique(
        id="T1234",
        name="Execution Technique",
        description="Test description",
        tactics=["execution"],
        platforms=["Windows"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.ENTERPRISE.value
    )
    
    persistence_tech = Technique(
        id="T5678",
        name="Persistence Technique",
        description="Test description",
        tactics=["persistence"],
        platforms=["Windows"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.ENTERPRISE.value
    )
    
    test_db.update_techniques([execution_tech, persistence_tech])
    
    # Test getting execution techniques
    execution_techniques = test_db.get_techniques_by_tactic("execution", MitreMatrix.ENTERPRISE)
    assert len(execution_techniques) == 1
    assert execution_techniques[0].id == "T1234"
    assert "execution" in execution_techniques[0].tactics
    
    # Test getting persistence techniques
    persistence_techniques = test_db.get_techniques_by_tactic("persistence", MitreMatrix.ENTERPRISE)
    assert len(persistence_techniques) == 1
    assert persistence_techniques[0].id == "T5678"
    assert "persistence" in persistence_techniques[0].tactics

def test_save_and_get_signature(test_db, sample_technique):
    """Test saving and retrieving signatures."""
    test_db.update_techniques([sample_technique])
    
    # Save a signature
    signature_content = "rule TestRule { strings: $a = \"test\" }"
    test_db.save_signature(sample_technique.id, "yara", signature_content)
    
    # Retrieve the signature
    saved_signature = test_db.get_signature(sample_technique.id, "yara")
    assert saved_signature == signature_content

def test_get_all_signatures(test_db, sample_technique):
    """Test retrieving all signatures of a specific format."""
    test_db.update_techniques([sample_technique])
    
    # Save multiple signatures
    yara_content = "rule TestRule { strings: $a = \"test\" }"
    sigma_content = "title: Test Rule\ndetection:\n  selection:\n    ProcessName: test.exe"
    
    test_db.save_signature(sample_technique.id, "yara", yara_content)
    test_db.save_signature(sample_technique.id, "sigma", sigma_content)
    
    # Test getting all YARA signatures
    yara_signatures = test_db.get_all_signatures("yara")
    assert len(yara_signatures) == 1
    assert yara_signatures[0]["technique_id"] == sample_technique.id
    assert yara_signatures[0]["content"] == yara_content
    
    # Test getting all Sigma signatures
    sigma_signatures = test_db.get_all_signatures("sigma")
    assert len(sigma_signatures) == 1
    assert sigma_signatures[0]["technique_id"] == sample_technique.id
    assert sigma_signatures[0]["content"] == sigma_content
