import os
import re
import argparse
import time
import requests
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# VirusTotal API Key (gunakan variabel lingkungan untuk keamanan)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Pola-pola umum untuk backdoor dan obfuscation dengan deskripsi dan dampak
SUSPICIOUS_PATTERNS = {
    "eval_execution": {
        "pattern": r"eval\s*\(",
        "description": "Penggunaan eval dapat dieksploitasi untuk mengeksekusi kode arbitrer.",
        "impact": "Eksekusi kode berbahaya."
    },
    "assert_execution": {
        "pattern": r"assert\s*\(",
        "description": "Assert dapat digunakan untuk menjalankan ekspresi PHP.",
        "impact": "Eksekusi kode berbahaya."
    },
    "preg_replace_execution": {
        "pattern": r"preg_replace\s*\(.*?/e",
        "description": "Penggunaan modifier 'e' pada preg_replace dapat digunakan untuk eksekusi kode.",
        "impact": "Eksekusi kode berbahaya."
    },
    "create_function_execution": {
        "pattern": r"create_function\s*\(",
        "description": "Fungsi create_function memungkinkan pembuatan kode secara dinamis.",
        "impact": "Eksekusi kode berbahaya."
    },
    "system_execution": {
        "pattern": r"system\s*\(",
        "description": "Fungsi system digunakan untuk menjalankan perintah shell.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "exec_execution": {
        "pattern": r"exec\s*\(",
        "description": "Fungsi exec digunakan untuk menjalankan perintah shell eksternal.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "shell_exec_execution": {
        "pattern": r"shell_exec\s*\(",
        "description": "Fungsi shell_exec digunakan untuk menjalankan perintah shell dan mengembalikan outputnya.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "passthru_execution": {
        "pattern": r"passthru\s*\(",
        "description": "Fungsi passthru digunakan untuk mengeksekusi perintah shell dan mengirimkan output secara langsung.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "pcntl_exec_execution": {
        "pattern": r"pcntl_exec\s*\(",
        "description": "Fungsi pcntl_exec digunakan untuk mengeksekusi program eksternal.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "backtick_execution": {
        "pattern": r"`[^`]+`",
        "description": "Penggunaan backtick memungkinkan eksekusi perintah shell.",
        "impact": "Eksekusi perintah sistem berbahaya."
    },
    "base64_decoding": {
        "pattern": r"base64_decode\s*\(",
        "description": "Decode base64 sering digunakan untuk menyembunyikan kode.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "str_rot13_decoding": {
        "pattern": r"str_rot13\s*\(",
        "description": "Fungsi str_rot13 dapat digunakan untuk menyembunyikan kode dengan enkripsi dasar.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "gzinflate_decoding": {
        "pattern": r"gzinflate\s*\(",
        "description": "Gzinflate digunakan untuk dekompresi data yang dapat menyembunyikan kode.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "gzuncompress_decoding": {
        "pattern": r"gzuncompress\s*\(",
        "description": "Gzuncompress digunakan untuk dekompresi data yang dapat menyembunyikan kode.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "gzdecode_decoding": {
        "pattern": r"gzdecode\s*\(",
        "description": "Gzdecode digunakan untuk dekompresi data yang dapat menyembunyikan kode.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "unserialize_decoding": {
        "pattern": r"unserialize\s*\(",
        "description": "Unserialize dapat digunakan untuk menjalankan payload berbahaya dalam data serialized.",
        "impact": "Eksekusi kode berbahaya."
    },
    "urldecode_decoding": {
        "pattern": r"urldecode\s*\(",
        "description": "Fungsi urldecode sering digunakan untuk mendekodekan data yang disembunyikan dalam URL.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "dynamic_variable": {
        "pattern": r"\$\{\s*['"]\\x[0-9a-fA-F]{2,}.*?['"]\s*\}",
        "description": "Variabel dinamis sering digunakan untuk menyamarkan kode berbahaya.",
        "impact": "Menyamarkan kode berbahaya."
    },
    "variable_variable": {
        "pattern": r"\$\$[a-zA-Z0-9_]+",
        "description": "Variabel variabel memungkinkan akses dinamis ke variabel lain.",
        "impact": "Menyamarkan kode berbahaya."
    },
    "dynamic_function_call": {
        "pattern": r"\$\w+\s*\(",
        "description": "Panggilan fungsi dinamis dapat digunakan untuk mengeksekusi fungsi berbahaya.",
        "impact": "Eksekusi kode berbahaya."
    },
    "file_write": {
        "pattern": r"(fwrite|file_put_contents)\s*\(",
        "description": "Fungsi ini digunakan untuk menulis file, dapat digunakan untuk menyebarkan malware.",
        "impact": "Pembuatan file berbahaya."
    },
    "file_read": {
        "pattern": r"(fread|file_get_contents)\s*\(",
        "description": "Fungsi ini digunakan untuk membaca file, dapat digunakan untuk mencuri data.",
        "impact": "Pencurian data."
    },
    "include_execution": {
        "pattern": r"(include|require)(_once)?\s*\(",
        "description": "Include atau require dapat digunakan untuk menyisipkan file berbahaya.",
        "impact": "Eksekusi kode berbahaya."
    },
    "globals_modification": {
        "pattern": r"\$_(GET|POST|COOKIE|REQUEST)\s*\[.*?\]\s*\(",
        "description": "Memodifikasi variabel global dapat memungkinkan injeksi kode.",
        "impact": "Eksekusi kode berbahaya."
    },
    "globals_variable": {
        "pattern": r"\$_(GET|POST|COOKIE|REQUEST)\s*\[.*?\]\s*=\s*",
        "description": "Manipulasi variabel global dapat memungkinkan eksploitasi data pengguna.",
        "impact": "Pencurian data atau injeksi."
    },
    "hexadecimal_obfuscation": {
        "pattern": r"\\x[0-9a-fA-F]{2}",
        "description": "Kode heksadesimal sering digunakan untuk menyembunyikan payload berbahaya.",
        "impact": "Menyembunyikan kode berbahaya."
    },
    "concatenation_obfuscation": {
        "pattern": r"['"].*?\.\s*['"]",
        "description": "Konkatenasi string dapat digunakan untuk menyamarkan kode berbahaya.",
        "impact": "Menyamarkan kode berbahaya."
    },
    "url_injection": {
        "pattern": r"https?://[^\s]+",
        "description": "URL eksternal dapat digunakan untuk memuat payload berbahaya.",
        "impact": "Pemanggilan kode atau data berbahaya."
    },
    "remote_execution": {
        "pattern": r"(preg_replace|create_function|eval|assert)\s*\(.*https?://.*\)",
        "description": "Eksekusi remote memungkinkan kode dieksekusi dari sumber eksternal.",
        "impact": "Eksekusi kode berbahaya dari jarak jauh."
    },
    "suspicious_function": {
        "pattern": r"(error_reporting\(0\)|ini_set\('display_errors', 0\))",
        "description": "Mematikan laporan error dapat digunakan untuk menyembunyikan aktivitas berbahaya.",
        "impact": "Menyembunyikan aktivitas berbahaya."
    },
}

# Fungsi untuk memindai file PHP berdasarkan pola mencurigakan
def scan_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.readlines()
            found_patterns = []

            # Periksa setiap baris dalam file
            for line_number, line in enumerate(content, start=1):
                for backdoor_type, details in SUSPICIOUS_PATTERNS.items():
                    if re.search(details["pattern"], line):
                        found_patterns.append({
                            "type": backdoor_type,
                            "description": details["description"],
                            "impact": details["impact"],
                            "line": line_number
                        })

            if found_patterns:
                return {
                    "file_path": filepath,
                    "patterns_found": found_patterns,
                    "extension": filepath.split('.')[-1],
                    "created_time": datetime.fromtimestamp(os.path.getctime(filepath)),
                    "modified_time": datetime.fromtimestamp(os.path.getmtime(filepath)),
                    "size_in_bytes": os.path.getsize(filepath),
                    "virus_total": scan_with_virustotal(filepath),
                }
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
    return None

# Fungsi untuk memindai file dengan VirusTotal
def scan_with_virustotal(filepath):
    if not VIRUSTOTAL_API_KEY:
        logging.warning("VirusTotal API key not set. Skipping VirusTotal scan.")
        return None

    try:
        with open(filepath, "rb") as file:
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                files={"file": file},
            )
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"VirusTotal scan failed for {filepath}: {response.status_code}")
    except Exception as e:
        logging.error(f"Error scanning with VirusTotal: {e}")
    return None

# Fungsi untuk menyimpan laporan ke file
def save_report(report_data, output_file):
    try:
        with open(output_file, 'w') as f:
            f.write("Suspicious File Scan Report\n")
            f.write("=" * 40 + "\n\n")
            for file_info in report_data:
                f.write(f"File: {file_info['file_path']}\n")
                f.write(f"  Extension: {file_info['extension']}\n")
                f.write(f"  Created Time: {file_info['created_time']}\n")
                f.write(f"  Modified Time: {file_info['modified_time']}\n")
                f.write(f"  Size: {file_info['size_in_bytes']} bytes\n")
                f.write(f"  Patterns Found:\n")
                for pattern in file_info['patterns_found']:
                    f.write(f"    - Type: {pattern['type']}\n")
                    f.write(f"      Description: {pattern['description']}\n")
                    f.write(f"      Impact: {pattern['impact']}\n")
                    f.write(f"      Line: {pattern['line']}\n")
                f.write(f"  VirusTotal Report: {file_info['virus_total']}\n\n")
        logging.info(f"Report saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

# Fungsi utama
def main():
    parser = argparse.ArgumentParser(description="Scan files for potential backdoors and check with VirusTotal.")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-x", "--extensions", nargs="*", default=[], help="File extensions to scan (e.g., php py). Default: all extensions.")
    parser.add_argument("-s", "--save", help="File to save the scan report")
    args = parser.parse_args()

    directory_to_scan = args.directory
    extensions_to_scan = args.extensions

    logging.info(f"Scanning directory: {directory_to_scan}")
    if extensions_to_scan:
        logging.info(f"Filtering by extensions: {', '.join(extensions_to_scan)}")
    else:
        logging.info("Scanning all file extensions.")

    suspicious_files = []
    total_files = sum(
        len(files) for _, _, files in os.walk(directory_to_scan)
        if not extensions_to_scan or any(file.split('.')[-1] in extensions_to_scan for file in files)
    )

    with ThreadPoolExecutor() as executor:
        futures = []
        for root, _, files in os.walk(directory_to_scan):
            for file in files:
                if not extensions_to_scan or file.split('.')[-1] in extensions_to_scan:
                    filepath = os.path.join(root, file)
                    futures.append(executor.submit(scan_file, filepath))

        for i, future in enumerate(futures, start=1):
            result = future.result()
            if result:
                suspicious_files.append(result)
            logging.info(f"Progress: {i}/{total_files} files scanned")

    if suspicious_files:
        logging.info("\nSuspicious files found:")
        for file_info in suspicious_files:
            logging.info(f"\nFile: {file_info['file_path']}")
            logging.info(f"  Extension: {file_info['extension']}")
            logging.info(f"  Created Time: {file_info['created_time']}")
            logging.info(f"  Modified Time: {file_info['modified_time']}")
            logging.info(f"  Size: {file_info['size_in_bytes']} bytes")
            logging.info(f"  Patterns Found:")
            for pattern in file_info['patterns_found']:
                logging.info(f"    - Type: {pattern['type']}")
                logging.info(f"      Description: {pattern['description']}")
                logging.info(f"      Impact: {pattern['impact']}")
                logging.info(f"      Line: {pattern['line']}")

    if args.save:
        save_report(suspicious_files, args.save)

if __name__ == "__main__":
    main()
