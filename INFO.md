### Info:

1. Core Components:

   - `api/`: MITRE ATT&CK API client for data fetching
   - `models/`: Data models for techniques and signatures
   - `converter/`: Signature converters for YARA, Sigma, and KQL
   - `database/`: Database models and handlers
   - `utils/`: Utility functions for logging, file handling, and configuration

2. Scripts:

   - `download_mitre.py`: Downloads and caches MITRE ATT&CK data
   - `update_database.py`: Updates the database with latest techniques
   - `generate_signatures.py`: Generates signatures for techniques

3. Configuration:

   - `config/config.ini`: Main application configuration
   - `config/logging_config.ini`: Logging configuration

4. Tests:

   - `test_database.py`: Database operation tests
   - `test_mitre_api.py`: API interaction tests
   - `test_converter.py`: Signature converter tests
   - Shared fixtures in `init.py`

5. Main Entry Points:
   - `main.py`: CLI interface with commands for:
     - Converting techniques to signatures
     - Exporting signatures to files
     - Listing techniques
     - Updating MITRE data

### Workflow:

1. Data Flow:

   - MITRE API → Technique Models → Converters → Signatures → Database/File Storage

2. Dependencies:

   - All components use the shared utility functions
   - Converters inherit from BaseConverter
   - Database operations are consistent across components
   - Logging is standardized throughout

3. Configuration:

   - All components use the ConfigHandler
   - Logging is configured consistently
   - File paths are handled uniformly

4. Testing:
   - Tests cover all major components
   - Shared fixtures reduce duplication
   - Mocking is used appropriately
