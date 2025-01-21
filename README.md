# Suspicious File Scanner with VirusTotal Integration

## Overview

This project is a Python-based tool for scanning files in a specified directory for potential backdoors, obfuscation, or other malicious code patterns. The tool integrates with the VirusTotal API to analyze suspicious files for further security validation.

### Features

- Detects suspicious patterns in files using customizable regex patterns.
- Scans all files or specific file types in a given directory.
- Integrates with VirusTotal API to check suspicious files.
- Saves scan results, including VirusTotal analysis, in a detailed JSON report.
- Easy configuration using external JSON files for suspicious patterns.

## Requirements

### Dependencies

- Python 3.7+
- Required Python libraries:
  - `requests`
  - `rich`
  - `argparse`
  - `concurrent.futures`

Install the required dependencies using pip:

```bash
pip install -r requirements.txt
```

### API Key

You need a VirusTotal API key to use the VirusTotal integration. Set it as an environment variable by creating a `.env` file in the root directory:

**.env file example:**

```
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Copy the provided `.env-sample` file as a starting point:

```bash
cp .env-sample .env
```

## Usage

### 1. Directory Structure

Ensure you have the following directory structure:

```
project/
|-- .env  # Environment variables
|-- .env-sample  # Example environment variables file
|-- .gitignore  # Git ignore file
|-- patterns.json  # JSON file containing suspicious patterns
|-- README.md  # Documentation file
|-- requirements.txt  # Python dependencies
|-- scanner.py  # Main script
```

### 2. Run the Scanner

Run the script with the following options:

```bash
python scanner.py -d /path/to/scan [options]
```

#### Command-line Arguments

| Argument           | Description                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| `-d, --directory`  | The directory to scan (required).                                                  |
| `-x, --extensions` | File extensions to scan (e.g., `php py`). Defaults to all extensions.              |
| `--patterns`       | Path to the JSON file containing suspicious patterns. Defaults to `patterns.json`. |
| `--virustotal`     | Enables VirusTotal integration for suspicious files.                               |
| `--save`           | Path to save the JSON report.                                                      |

#### Examples

**Scan all files in a directory:**

```bash
python scanner.py -d /path/to/scan
```

**Scan only `.php` and `.py` files:**

```bash
python scanner.py -d /path/to/scan -x php py
```

**Enable VirusTotal checks and save the report:**

```bash
python scanner.py -d /path/to/scan --virustotal --save results.json
```

## Configuration

### Suspicious Patterns (`patterns.json`)

Suspicious patterns are stored in a separate JSON file (`patterns.json`). You can customize or add new patterns.

**Example format:**

```json
{
  "eval_execution": {
    "pattern": "eval\\s*\\(",
    "description": "Penggunaan eval dapat dieksploitasi untuk mengeksekusi kode arbitrer.",
    "impact": "Eksekusi kode berbahaya."
  },
  "base64_decoding": {
    "pattern": "base64_decode\\s*\\(",
    "description": "Decode base64 sering digunakan untuk menyembunyikan kode.",
    "impact": "Menyembunyikan kode berbahaya."
  }
}
```

### VirusTotal Integration

To enable VirusTotal integration:

1. Obtain an API key from [VirusTotal](https://www.virustotal.com/).
2. Add the API key to your `.env` file:
   ```bash
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

## Output

### Console Output

The script provides a summary of suspicious files found, including:

- File path
- Detected patterns
- Line numbers

### JSON Report

If `--save` is specified, the scan results are saved in a JSON file. The report includes:

- File details (path, size, timestamps, etc.)
- Detected patterns with descriptions and impacts
- VirusTotal analysis (if enabled), including:
  - Safety status (`is_safe`)
  - Malicious detection count
  - Link to VirusTotal analysis

**Example Report:**

```json
[
  {
    "file_path": "/path/to/suspicious.php",
    "extension": "php",
    "created_time": "2025-01-21 10:15:30",
    "modified_time": "2025-01-21 10:30:45",
    "size_in_bytes": 2048,
    "patterns_found": [
      {
        "type": "eval_execution",
        "description": "Penggunaan eval dapat dieksploitasi untuk mengeksekusi kode arbitrer.",
        "impact": "Eksekusi kode berbahaya.",
        "line": 15
      }
    ],
    "virustotal": {
      "is_safe": false,
      "malicious_count": 3,
      "analysis_link": "https://www.virustotal.com/gui/file/<file_hash>"
    }
  }
]
```

## Error Handling

- If a file cannot be read, an error message will be logged.
- If the VirusTotal API is unavailable or the API key is invalid, a corresponding error will be displayed.

## Limitations

- VirusTotal API requests are limited by your API key's quota.
- The tool relies on regex patterns and may produce false positives or false negatives.

## Contributing

Feel free to contribute by:

- Adding new suspicious patterns.
- Improving the VirusTotal integration.
- Enhancing performance and functionality.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
