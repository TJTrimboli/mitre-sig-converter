import pytest
from mitre_sig_converter.api import MitreApi
from unittest.mock import patch, MagicMock

@pytest.fixture
def mitre_api():
    return MitreApi()

def test_get_enterprise_matrix(mitre_api):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'matrices': [
                {
                    'name': 'Enterprise ATT&CK',
                    'tactics': ['tactic1', 'tactic2']
                }
            ]
        }
        mock_get.return_value = mock_response
        
        matrix = mitre_api.get_enterprise_matrix()
        assert matrix is not None
        assert 'tactics' in matrix
        assert len(matrix['tactics']) == 2

def test_get_all_techniques(mitre_api):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'techniques': [
                {
                    'technique_id': 'T1055',
                    'name': 'Process Injection',
                    'description': 'Test description'
                },
                {
                    'technique_id': 'T1056',
                    'name': 'Input Capture',
                    'description': 'Test description'
                }
            ]
        }
        mock_get.return_value = mock_response
        
        techniques = mitre_api.get_all_techniques()
        assert techniques is not None
        assert len(techniques) == 2
        assert techniques[0]['technique_id'] == 'T1055'
        assert techniques[1]['technique_id'] == 'T1056'

def test_get_tactics(mitre_api):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'tactics': [
                {
                    'tactic_id': 'TA0001',
                    'name': 'Initial Access',
                    'description': 'Test description'
                },
                {
                    'tactic_id': 'TA0002',
                    'name': 'Execution',
                    'description': 'Test description'
                }
            ]
        }
        mock_get.return_value = mock_response
        
        tactics = mitre_api.get_tactics()
        assert tactics is not None
        assert len(tactics) == 2
        assert tactics[0]['tactic_id'] == 'TA0001'
        assert tactics[1]['tactic_id'] == 'TA0002'

def test_api_error_handling(mitre_api):
    with patch('requests.get') as mock_get:
        mock_get.side_effect = Exception('API Error')
        
        with pytest.raises(Exception):
            mitre_api.get_all_techniques()
