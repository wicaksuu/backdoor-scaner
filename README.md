# PHP Backdoor Scanner with VirusTotal Integration

This project is a Python-based script designed to scan directories for potential backdoor files. It analyzes PHP and other files for suspicious patterns, obfuscation, and other indicators of malicious code. The script integrates with **VirusTotal** to provide additional security checks for suspicious files.

## Features
- **Pattern Detection:** Identifies common backdoor patterns like `eval()`, `base64_decode()`, dynamic variables, and obfuscated strings.
- **Integration with VirusTotal:** Automatically submits suspicious files to VirusTotal for further analysis.
- **Real-Time Progress:** Displays the current file being scanned, percentage completion, and estimated time remaining.
- **Extension Filtering:** Allows scanning specific file extensions (e.g., `php`, `py`).
- **Detailed Reports:** Provides comprehensive details about suspicious files, including patterns found, creation/modification timestamps, file size, and more.
- **Report Saving:** Saves scan results to a file for further analysis.

## How It Works
1. **Pattern Matching:** The script uses regular expressions to match suspicious patterns in file content.
2. **Recursive Scanning:** It traverses the specified directory and all its subdirectories to find files matching the specified extensions.
3. **VirusTotal Integration:** Suspicious files are automatically submitted to VirusTotal for further analysis (requires an API key).
4. **Progress Tracking:** Real-time updates on scanning progress, including file count and estimated time remaining.
5. **Detailed Analysis:** Extracts metadata like creation time, modification time, and file size for each suspicious file.
6. **Report Generation:** Optionally saves results to a text file for documentation and further investigation.

## Installation
### Prerequisites
1. **Python 3.6+**
2. Install required packages:
   ```bash
   pip install requests
   ```

### VirusTotal API Key
Obtain your VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us) and replace the `VIRUSTOTAL_API_KEY` in the script.

## Usage
Run the script with the following commands:

### Basic Scan
Scan all files in a directory:
```bash
python scan_backdoor.py -d "/path/to/directory"
```

### Filter by File Extensions
Scan only specific file types (e.g., PHP and Python files):
```bash
python scan_backdoor.py -d "/path/to/directory" -x php py
```

### Save Scan Report
Save the scan results to a text file:
```bash
python scan_backdoor.py -d "/path/to/directory" -s report.txt
```

### Combine Extension Filtering and Report Saving
```bash
python scan_backdoor.py -d "/path/to/directory" -x php -s report_php.txt
```

## Output Format
### Console Output
Real-time status updates during scanning, including:
- File being scanned
- Percentage completed
- Estimated time remaining

Example:
```plaintext
Scanning directory: /var/www/
Filtering by extensions: php

Scanning: /var/www/index.php | 12/120 files (10.00%) | Estimated time remaining: 45.23 seconds
...
Suspicious files found:

File: /var/www/backdoor.php
  Patterns Found: eval_execution, base64_decoding
  Extension: php
  Created Time: 2025-01-15 10:30:00
  Modified Time: 2025-01-19 15:45:00
  Size: 2345 bytes
  VirusTotal Report: {...}
```

### Saved Report
When using the `-s` option, the report is saved in plain text format. Example:
```plaintext
Suspicious File Scan Report
========================================

File: /var/www/backdoor.php
  Patterns Found: eval_execution, base64_decoding
  Extension: php
  Created Time: 2025-01-15 10:30:00
  Modified Time: 2025-01-19 15:45:00
  Size: 2345 bytes
  VirusTotal Report: {...}
```

## Advanced Features
### Supported Patterns
The script detects various backdoor techniques, including:
- **Dynamic Execution:** `eval()`, `assert()`, `create_function()`
- **System Commands:** `exec()`, `system()`, `shell_exec()`
- **Obfuscation:** Hexadecimal (`\xNN`), base64 encoding, ROT13
- **File Manipulation:** `fwrite()`, `file_put_contents()`
- **Remote Code Inclusion:** URLs in `preg_replace`, `eval`

### VirusTotal Integration
- Suspicious files are submitted to VirusTotal for further analysis.
- Reports from VirusTotal include additional security checks for uploaded files.

### Estimation and Progress
- Displays real-time progress updates.
- Calculates estimated time remaining based on current scanning speed.

## Contributing
Feel free to contribute by submitting pull requests or reporting issues. Any additional pattern suggestions are welcome.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
