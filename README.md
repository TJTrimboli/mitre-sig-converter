# MITRE ATT&CK Signature Converter

A comprehensive Python application that converts MITRE ATT&CK techniques into common signature types used by cybersecurity teams.

## Features

- Converts MITRE ATT&CK techniques and sub-techniques to:
  - YARA signatures
  - Sigma rules
  - KQL (Kusto Query Language) queries
- Maintains a local database of techniques and their corresponding signatures
- Command-line interface for batch conversion
- Ability to export signatures to various formats

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mitre-sig-converter.git
cd mitre-sig-converter
```

2. Install the package:
```bash
pip install -e .
```

3. Download the latest MITRE ATT&CK data:
```bash
python scripts/download_mitre.py
```

## Usage

### Command Line Interface

Convert all techniques to signature formats:
```bash
python -m mitre_sig_converter convert --all
```

Convert specific technique:
```bash
python -m mitre_sig_converter convert --technique T1055
```

Convert techniques by tactic:
```bash
python -m mitre_sig_converter convert --tactic "defense-evasion"
```

Export all signatures to files:
```bash
python -m mitre_sig_converter export --output ./signatures
```

### Using as a Library

```python
from mitre_sig_converter.api import MitreApi
from mitre_sig_converter.converter import YaraConverter, SigmaConverter, KqlConverter

# Load MITRE data
mitre_api = MitreApi()
techniques = mitre_api.get_all_techniques()

# Convert a technique to YARA
yara_converter = YaraConverter()
yara_rule = yara_converter.convert(techniques[0])
print(yara_rule)

# Convert a technique to Sigma
sigma_converter = SigmaConverter()
sigma_rule = sigma_converter.convert(techniques[0])
print(sigma_rule)

# Convert a technique to KQL
kql_converter = KqlConverter()
kql_query = kql_converter.convert(techniques[0])
print(kql_query)
```

## Configuration

Configuration options can be modified in `config/config.ini`.

## License

MIT License