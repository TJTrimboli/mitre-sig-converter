# MITRE ATT&CK Signature Converter

A Python application that converts MITRE ATT&CK techniques into common signature types (YARA, Sigma, and KQL) used by cybersecurity teams. The tool creates and maintains a database of techniques and their corresponding signatures, which can be used across different environments (Windows, Linux, macOS, and cloud).

## Features

- Fetches and stores MITRE ATT&CK techniques
- Converts techniques to multiple signature formats:
  - YARA rules
  - Sigma rules
  - KQL (Kusto Query Language) queries
- Environment-agnostic detection rules
- Local SQLite database for technique and signature storage
- Command-line interface for easy integration
- Comprehensive logging and error handling

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/mitre-sig-converter.git
cd mitre-sig-converter
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Update MITRE ATT&CK Database

To fetch and store the latest MITRE ATT&CK techniques:

```bash
python scripts/update_database.py [--db-url DB_URL] [--log-file LOG_FILE]
```

Options:

- `--db-url`: Database URL (default: sqlite:///data/techniques.db)
- `--log-file`: Log file path (default: logs/update_database.log)

### Generate Signatures

To generate signatures for stored techniques:

```bash
python scripts/generate_signatures.py [--db-url DB_URL] [--output-dir OUTPUT_DIR] [--log-file LOG_FILE] [--technique-id TECHNIQUE_ID]
```

Options:

- `--db-url`: Database URL (default: sqlite:///data/techniques.db)
- `--output-dir`: Output directory for generated signatures (default: output)
- `--log-file`: Log file path (default: logs/generate_signatures.log)
- `--technique-id`: Generate signatures for a specific technique ID (optional)

## Project Structure

```
mitre-sig-converter/
├── mitre_sig_converter/     # Main package
│   ├── api/                # MITRE ATT&CK API client
│   ├── converter/          # Signature converters
│   ├── database/          # Database models and handlers
│   ├── models/            # Data models
│   └── utils/             # Utility functions
├── scripts/               # Command-line scripts
├── tests/                # Test cases
├── data/                 # Data storage
├── config/              # Configuration files
├── requirements.txt     # Python dependencies
└── README.md           # Project documentation
```

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Adding New Signature Types

1. Create a new converter class in `mitre_sig_converter/converter/`
2. Inherit from `BaseConverter` and implement required methods
3. Update the signature generation script to include the new converter

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
