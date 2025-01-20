import os
import re
import argparse
import time
import requests
from datetime import datetime

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# Pola-pola umum untuk backdoor dan obfuscation
SUSPICIOUS_PATTERNS = {
    "eval_execution": r"eval\s*\(",
    "assert_execution": r"assert\s*\(",
    "preg_replace_execution": r"preg_replace\s*\(.*?/e",
    "create_function_execution": r"create_function\s*\(",
    "system_execution": r"system\s*\(",
    "exec_execution": r"exec\s*\(",
    "shell_exec_execution": r"shell_exec\s*\(",
    "passthru_execution": r"passthru\s*\(",
    "pcntl_exec_execution": r"pcntl_exec\s*\(",
    "backtick_execution": r"`[^`]+`",
    "base64_decoding": r"base64_decode\s*\(",
    "str_rot13_decoding": r"str_rot13\s*\(",
    "gzinflate_decoding": r"gzinflate\s*\(",
    "gzuncompress_decoding": r"gzuncompress\s*\(",
    "gzdecode_decoding": r"gzdecode\s*\(",
    "unserialize_decoding": r"unserialize\s*\(",
    "urldecode_decoding": r"urldecode\s*\(",
    "dynamic_variable": r"\$\{\s*['\"]\\x[0-9a-fA-F]{2,}.*?['\"]\s*\}",
    "variable_variable": r"\$\$[a-zA-Z0-9_]+",
    "dynamic_function_call": r"\$\w+\s*\(",
    "file_write": r"(fwrite|file_put_contents)\s*\(",
    "file_read": r"(fread|file_get_contents)\s*\(",
    "include_execution": r"(include|require)(_once)?\s*\(",
    "globals_modification": r"\$_(GET|POST|COOKIE|REQUEST)\s*\[.*?\]\s*\(",
    "globals_variable": r"\$_(GET|POST|COOKIE|REQUEST)\s*\[.*?\]\s*=\s*",
    "hexadecimal_obfuscation": r"\\x[0-9a-fA-F]{2}",
    "concatenation_obfuscation": r"['\"].*?\.\s*['\"]",
    "url_injection": r"https?://[^\s]+",
    "remote_execution": r"(preg_replace|create_function|eval|assert)\s*\(.*https?://.*\)",
    "suspicious_function": r"(error_reporting\(0\)|ini_set\('display_errors', 0\))",
}

# Fungsi untuk memindai file PHP berdasarkan pola mencurigakan
def scan_files(directory, extensions):
    suspicious_files = []
    total_files = 0

    # Hitung jumlah total file yang akan dipindai
    for root, _, files in os.walk(directory):
        for file in files:
            if not extensions or file.split('.')[-1] in extensions:
                total_files += 1

    scanned_files = 0
    start_time = time.time()

    for root, dirs, files in os.walk(directory):
        for file in files:
            if not extensions or file.split('.')[-1] in extensions:
                filepath = os.path.join(root, file)
                scanned_files += 1
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        found_patterns = []

                        # Periksa setiap pola dalam file
                        for backdoor_type, pattern in SUSPICIOUS_PATTERNS.items():
                            if re.search(pattern, content):
                                found_patterns.append(backdoor_type)

                        if found_patterns:
                            file_info = {
                                "file_path": filepath,
                                "patterns_found": found_patterns,
                                "extension": file.split('.')[-1],
                                "created_time": datetime.fromtimestamp(os.path.getctime(filepath)),
                                "modified_time": datetime.fromtimestamp(os.path.getmtime(filepath)),
                                "size_in_bytes": os.path.getsize(filepath),
                                "virus_total": scan_with_virustotal(filepath),
                            }
                            suspicious_files.append(file_info)

                except Exception as e:
                    print(f"Error reading file {filepath}: {e}")

                # Tampilkan status proses
                elapsed_time = time.time() - start_time
                remaining_time = (elapsed_time / scanned_files) * (total_files - scanned_files) if scanned_files else 0
                progress = (scanned_files / total_files) * 100
                print(
                    f"\rScanning: {filepath} | {scanned_files}/{total_files} files ({progress:.2f}%) | "
                    f"Estimated time remaining: {remaining_time:.2f} seconds", end=""
                )
    print()  # Pindah ke baris baru setelah scan selesai
    return suspicious_files

# Fungsi untuk memindai file dengan VirusTotal
def scan_with_virustotal(filepath):
    if not VIRUSTOTAL_API_KEY:
        print("VirusTotal API key not set. Skipping VirusTotal scan.")
        return None

    with open(filepath, "rb") as file:
        try:
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                files={"file": file},
            )
            if response.status_code == 200:
                return response.json()
            else:
                print(f"VirusTotal scan failed for {filepath}: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error scanning with VirusTotal: {e}")
            return None

# Fungsi untuk menyimpan laporan ke file
def save_report(report_data, output_file):
    try:
        with open(output_file, 'w') as f:
            f.write("Suspicious File Scan Report\n")
            f.write("=" * 40 + "\n\n")
            for file_info in report_data:
                f.write(f"File: {file_info['file_path']}\n")
                f.write(f"  Patterns Found: {', '.join(file_info['patterns_found'])}\n")
                f.write(f"  Extension: {file_info['extension']}\n")
                f.write(f"  Created Time: {file_info['created_time']}\n")
                f.write(f"  Modified Time: {file_info['modified_time']}\n")
                f.write(f"  Size: {file_info['size_in_bytes']} bytes\n")
                f.write(f"  VirusTotal Report: {file_info['virus_total']}\n\n")
        print(f"\nReport saved to {output_file}")
    except Exception as e:
        print(f"Error saving report: {e}")

# Main program
def main():
    parser = argparse.ArgumentParser(description="Scan files for potential backdoors and check with VirusTotal.")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-x", "--extensions", nargs="*", default=[], help="File extensions to scan (e.g., php py). Default: all extensions.")
    parser.add_argument("-s", "--save", help="File to save the scan report")
    args = parser.parse_args()

    directory_to_scan = args.directory
    extensions_to_scan = args.extensions

    print(f"Scanning directory: {directory_to_scan}")
    if extensions_to_scan:
        print(f"Filtering by extensions: {', '.join(extensions_to_scan)}")
    else:
        print("Scanning all file extensions.")

    suspicious_files = scan_files(directory_to_scan, extensions_to_scan)

    if suspicious_files:
        print("\nSuspicious files found:")
        for file_info in suspicious_files:
            print(f"\nFile: {file_info['file_path']}")
            print(f"  Patterns Found: {', '.join(file_info['patterns_found'])}")
            print(f"  Extension: {file_info['extension']}")
            print(f"  Created Time: {file_info['created_time']}")
            print(f"  Modified Time: {file_info['modified_time']}")
            print(f"  Size: {file_info['size_in_bytes']} bytes")
            if file_info['virus_total']:
                print(f"  VirusTotal Report: {file_info['virus_total']}")

    if args.save:
        save_report(suspicious_files, args.save)

if __name__ == "__main__":
    main()
