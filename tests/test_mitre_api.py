"""
Tests for the MITRE API client.
"""

import pytest
from pathlib import Path
import json
import shutil

from mitre_sig_converter.api.mitre_api import MitreApi, MitreMatrix
from mitre_sig_converter.utils.config_handler import ConfigHandler

@pytest.fixture
def sample_mitre_data():
    """Create sample MITRE ATT&CK data for testing."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test1",
                "name": "Test Technique 1",
                "description": "Test description 1",
                "external_references": [
                    {
                        "source_name": "mitre-enterprise",
                        "external_id": "T1234"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-enterprise",
                        "phase_name": "execution"
                    }
                ],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_data_sources": ["Process Monitoring"],
                "x_mitre_detection": "Test detection 1"
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test2",
                "name": "Test Technique 2",
                "description": "Test description 2",
                "external_references": [
                    {
                        "source_name": "mitre-mobile",
                        "external_id": "T5678"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-mobile",
                        "phase_name": "execution"
                    }
                ],
                "x_mitre_platforms": ["Android"],
                "x_mitre_data_sources": ["Process Monitoring"],
                "x_mitre_detection": "Test detection 2"
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test3",
                "name": "Test Technique 3",
                "description": "Test description 3",
                "external_references": [
                    {
                        "source_name": "mitre-ics",
                        "external_id": "T9012"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-ics",
                        "phase_name": "execution"
                    }
                ],
                "x_mitre_platforms": ["Control Server"],
                "x_mitre_data_sources": ["Process Monitoring"],
                "x_mitre_detection": "Test detection 3"
            }
        ]
    }

@pytest.fixture
def test_data_dir(tmp_path, sample_mitre_data):
    """Create a temporary directory with test data."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    
    # Save sample data for each matrix
    for matrix in MitreMatrix:
        file_path = data_dir / f"{matrix.value}-attack.json"
        with open(file_path, "w") as f:
            json.dump(sample_mitre_data, f)
    
    # Print the contents of the directory for debugging
    print("\nTest data directory contents:")
    for file in data_dir.iterdir():
        print(f"- {file}")
    
    return data_dir

@pytest.fixture
def config_handler(test_data_dir):
    """Create a configuration handler with test paths."""
    config = ConfigHandler()
    config.config = {
        'MITRE': {
            'enterprise_file': str(test_data_dir / "enterprise-attack.json"),
            'mobile_file': str(test_data_dir / "mobile-attack.json"),
            'ics_file': str(test_data_dir / "ics-attack.json")
        }
    }
    
    # Print the config for debugging
    print("\nConfig contents:")
    print(config.config)
    
    return config

def test_mitre_api_enterprise(config_handler):
    """Test MITRE API with Enterprise matrix."""
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    techniques = api.get_all_techniques()
    
    assert len(techniques) == 1
    assert techniques[0].id == "T1234"
    assert techniques[0].name == "Test Technique 1"
    assert techniques[0].matrix == "enterprise"

def test_mitre_api_mobile(config_handler):
    """Test MITRE API with Mobile matrix."""
    api = MitreApi(MitreMatrix.MOBILE, config_handler=config_handler)
    techniques = api.get_all_techniques()
    
    assert len(techniques) == 1
    assert techniques[0].id == "T5678"
    assert techniques[0].name == "Test Technique 2"
    assert techniques[0].matrix == "mobile"

def test_mitre_api_ics(config_handler):
    """Test MITRE API with ICS matrix."""
    api = MitreApi(MitreMatrix.ICS, config_handler=config_handler)
    techniques = api.get_all_techniques()
    
    assert len(techniques) == 1
    assert techniques[0].id == "T9012"
    assert techniques[0].name == "Test Technique 3"
    assert techniques[0].matrix == "ics"

def test_get_technique_by_id(config_handler):
    """Test getting a technique by ID."""
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    technique = api.get_technique_by_id("T1234")
    
    assert technique is not None
    assert technique.id == "T1234"
    assert technique.name == "Test Technique 1"

def test_get_techniques_by_tactic(config_handler):
    """Test getting techniques by tactic."""
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    techniques = api.get_techniques_by_tactic("execution")
    
    assert len(techniques) == 1
    assert techniques[0].id == "T1234"
    assert "execution" in techniques[0].tactics

def test_get_subtechniques(config_handler):
    """Test getting sub-techniques."""
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    subtechniques = api.get_subtechniques("T1234")
    
    assert len(subtechniques) == 0  # No sub-techniques in sample data

def test_get_parent_technique(config_handler):
    """Test getting parent technique."""
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    parent = api.get_parent_technique("T1234.001")
    
    assert parent is None  # No parent technique in sample data

def test_invalid_matrix():
    """Test handling of invalid matrix."""
    with pytest.raises(ValueError):
        MitreApi("invalid_matrix")

def test_missing_data_file(config_handler):
    """Test handling of missing data file."""
    # Remove the enterprise data file
    Path(config_handler.get('MITRE.enterprise_file')).unlink()
    
    api = MitreApi(MitreMatrix.ENTERPRISE, config_handler=config_handler)
    techniques = api.get_all_techniques()
    
    assert len(techniques) == 0
