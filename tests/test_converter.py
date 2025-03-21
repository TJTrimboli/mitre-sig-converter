"""
Tests for the signature converters.
"""

import pytest
from pathlib import Path

from mitre_sig_converter.converter import YaraConverter, SigmaConverter, KqlConverter
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
def sample_subtechnique():
    """Create a sample sub-technique for testing."""
    return Technique(
        id="T1234.001",
        name="Test Sub-technique",
        description="Test sub-technique description",
        tactics=["execution"],
        platforms=["Windows"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=["T1234"],
        is_subtechnique=True,
        matrix=MitreMatrix.ENTERPRISE.value
    )

def test_yara_converter(sample_technique):
    """Test YARA converter."""
    converter = YaraConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert "rule" in signature
    assert sample_technique.id in signature
    assert sample_technique.name in signature
    assert "strings:" in signature
    assert "condition:" in signature

def test_yara_converter_subtechnique(sample_subtechnique):
    """Test YARA converter with sub-technique."""
    converter = YaraConverter()
    signature = converter.convert(sample_subtechnique)
    
    assert signature is not None
    assert "rule" in signature
    assert sample_subtechnique.id in signature
    assert sample_subtechnique.name in signature
    assert "strings:" in signature
    assert "condition:" in signature

def test_sigma_converter(sample_technique):
    """Test Sigma converter."""
    converter = SigmaConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert "title:" in signature
    assert sample_technique.id in signature
    assert sample_technique.name in signature
    assert "detection:" in signature
    assert "selection:" in signature

def test_sigma_converter_subtechnique(sample_subtechnique):
    """Test Sigma converter with sub-technique."""
    converter = SigmaConverter()
    signature = converter.convert(sample_subtechnique)
    
    assert signature is not None
    assert "title:" in signature
    assert sample_subtechnique.id in signature
    assert sample_subtechnique.name in signature
    assert "detection:" in signature
    assert "selection:" in signature

def test_kql_converter(sample_technique):
    """Test KQL converter."""
    converter = KqlConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert "let" in signature
    assert sample_technique.id in signature
    assert sample_technique.name in signature
    assert "| where" in signature

def test_kql_converter_subtechnique(sample_subtechnique):
    """Test KQL converter with sub-technique."""
    converter = KqlConverter()
    signature = converter.convert(sample_subtechnique)
    
    assert signature is not None
    assert "let" in signature
    assert sample_subtechnique.id in signature
    assert sample_subtechnique.name in signature
    assert "| where" in signature

def test_converter_error_handling():
    """Test error handling in converters."""
    converters = [YaraConverter(), SigmaConverter(), KqlConverter()]
    
    for converter in converters:
        with pytest.raises(ValueError):
            converter.convert(None)

def test_converter_matrix_specific(sample_technique):
    """Test converters with different matrices."""
    # Test Enterprise matrix
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
    
    # Test Mobile matrix
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
    
    # Test ICS matrix
    ics_tech = Technique(
        id="T9012",
        name="ICS Technique",
        description="Test description",
        tactics=["execution"],
        platforms=["Control Server"],
        data_sources=["Process Monitoring"],
        detection="Test detection",
        related_techniques=[],
        is_subtechnique=False,
        matrix=MitreMatrix.ICS.value
    )
    
    converters = [YaraConverter(), SigmaConverter(), KqlConverter()]
    
    for converter in converters:
        # Test Enterprise conversion
        enterprise_sig = converter.convert(enterprise_tech)
        assert enterprise_sig is not None
        assert enterprise_tech.id in enterprise_sig
        assert enterprise_tech.matrix in enterprise_sig.lower()
        
        # Test Mobile conversion
        mobile_sig = converter.convert(mobile_tech)
        assert mobile_sig is not None
        assert mobile_tech.id in mobile_sig
        assert mobile_tech.matrix in mobile_sig.lower()
        
        # Test ICS conversion
        ics_sig = converter.convert(ics_tech)
        assert ics_sig is not None
        assert ics_tech.id in ics_sig
        assert ics_tech.matrix in ics_sig.lower()
