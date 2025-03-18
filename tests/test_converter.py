import pytest
from mitre_sig_converter.converter import YaraConverter, SigmaConverter, KqlConverter
from mitre_sig_converter.models import Technique

@pytest.fixture
def sample_technique():
    return Technique.from_dict({
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Process injection is a method of executing arbitrary code...',
        'platforms': ['Windows', 'Linux'],
        'data_sources': ['Process monitoring', 'API monitoring']
    })

def test_yara_converter(sample_technique):
    converter = YaraConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert 'rule T1055_Process_Injection' in signature
    assert 'meta:' in signature
    assert 'strings:' in signature
    assert 'condition:' in signature

def test_sigma_converter(sample_technique):
    converter = SigmaConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert 'title: Process Injection' in signature
    assert 'id: T1055' in signature
    assert 'status: experimental' in signature
    assert 'detection:' in signature

def test_kql_converter(sample_technique):
    converter = KqlConverter()
    signature = converter.convert(sample_technique)
    
    assert signature is not None
    assert 'let timeframe = 1h;' in signature
    assert 'union *' in signature
    assert 'where' in signature

def test_converter_error_handling():
    converters = [YaraConverter(), SigmaConverter(), KqlConverter()]
    invalid_technique = None
    
    for converter in converters:
        with pytest.raises(ValueError):
            converter.convert(invalid_technique)
