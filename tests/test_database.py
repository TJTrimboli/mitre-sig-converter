import pytest
from mitre_sig_converter.database import DatabaseHandler, Technique, Signature
from datetime import datetime, UTC

@pytest.fixture
def db():
    db = DatabaseHandler('sqlite:///:memory:')
    db.init_db()
    return db

def test_add_technique(db):
    technique_data = {
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Test description',
        'platform': 'Windows,Linux'
    }
    
    technique = db.add_technique(technique_data)
    assert technique is not None
    assert technique.technique_id == 'T1055'
    assert technique.name == 'Process Injection'

def test_add_signature(db):
    # First add a technique
    technique = db.add_technique({
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Test description',
        'platform': 'Windows,Linux'
    })
    
    signature_data = {
        'technique_id': technique.id,
        'signature_type': 'yara',
        'content': 'rule test_rule { condition: true }',
        'metadata': {'test': 'metadata'}
    }
    
    signature = db.add_signature(signature_data)
    assert signature is not None
    assert signature.signature_type == 'yara'
    assert signature.technique_id == technique.id

def test_get_technique(db):
    # Add a technique
    technique_data = {
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Test description',
        'platform': 'Windows,Linux'
    }
    db.add_technique(technique_data)
    
    # Get the technique
    technique = db.get_technique('T1055')
    assert technique is not None
    assert technique.technique_id == 'T1055'
    assert technique.name == 'Process Injection'

def test_update_technique(db):
    # Add a technique
    technique_data = {
        'technique_id': 'T1055',
        'name': 'Process Injection',
        'description': 'Test description',
        'platform': 'Windows,Linux'
    }
    db.add_technique(technique_data)
    
    # Update the technique
    update_data = {
        'name': 'Updated Process Injection',
        'description': 'Updated description'
    }
    success = db.update_technique('T1055', update_data)
    assert success
    
    # Verify update
    technique = db.get_technique('T1055')
    assert technique.name == 'Updated Process Injection'
    assert technique.description == 'Updated description'
