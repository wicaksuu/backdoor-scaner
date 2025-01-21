# PHP Backdoor Scanner

PHP Backdoor Scanner is a Python-based tool designed to detect suspicious patterns in PHP and other files, often indicative of backdoors or malicious activity. The tool also integrates with VirusTotal for an additional layer of threat analysis.

## Features
- Detects common backdoor patterns in PHP files.
- Provides detailed insights including file metadata, suspicious patterns, and their locations in the file.
- Integrates with VirusTotal to analyze files for known threats.
- Outputs results in a structured and visually appealing table using `Rich`.
- Saves scan results to a report file if specified.

---

## Prerequisites
Ensure the following are installed:
- Python 3.7 or higher
- `pip` (Python package manager)

---

## Installation
1. Clone this repository or download the source code:
   ```bash
   git clone https://github.com/your-repo/php-backdoor-scanner.git
   cd php-backdoor-scanner
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration
### Environment Variables
Create a `.env` file in the project directory with the following content:
```plaintext
# .env file
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```
Replace `your_virustotal_api_key` with a valid API key from [VirusTotal](https://www.virustotal.com).

---

## Usage
Run the scanner using the following command:
```bash
python scanner.py -d <directory_to_scan> [-x <extensions>] [-s <report_file>]
```

### Arguments:
- `-d` or `--directory`: The directory to scan (required).
- `-x` or `--extensions`: File extensions to scan (e.g., `php py`). If omitted, scans all extensions (optional).
- `-s` or `--save`: File path to save the scan report (optional).

### Examples:
1. Scan a directory for all files:
   ```bash
   python scanner.py -d /path/to/scan
   ```

2. Scan only PHP files and save the report:
   ```bash
   python scanner.py -d /path/to/scan -x php -s report.txt
   ```

---

## Output
The results will be displayed in a visually appealing table format, including:
- File path
- File extension
- Created and modified times
- File size
- Detected patterns, including their types, descriptions, impacts, and line numbers

If a report file is specified, the results will also be saved in plain text format.

---

## Dependencies
The tool requires the following Python libraries:
- `rich`: For enhanced terminal output.
- `python-dotenv`: For loading environment variables from the `.env` file.
- `requests`: For interacting with the VirusTotal API.

To install these dependencies, use:
```bash
pip install -r requirements.txt
```

---

## Development
### Adding New Patterns
You can extend the detection capability by adding new patterns to the `SUSPICIOUS_PATTERNS` dictionary in the script. Each pattern requires:
- `pattern`: The regex to match.
- `description`: A brief explanation of the pattern.
- `impact`: The potential impact of the pattern.

### Example:
```python
"example_pattern": {
    "pattern": r"example_regex",
    "description": "Description of the pattern.",
    "impact": "Impact of the pattern."
}
```

---

## Contributing
Contributions are welcome! Feel free to fork the repository and submit pull requests for improvements or additional features.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments
- [VirusTotal](https://www.virustotal.com) for their comprehensive threat database.
- [Rich](https://github.com/Textualize/rich) for providing an excellent library for terminal output.

---

## Support
For any issues or questions, please open an issue on the [GitHub repository](https://github.com/wicaksuu/backdoor-scaner).

