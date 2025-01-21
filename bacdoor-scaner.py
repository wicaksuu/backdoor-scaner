import os
import re
import argparse
import time
import requests
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
console = Console()

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
                }
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
    return None

# Fungsi untuk menampilkan hasil dengan Rich
def display_results(results):
    table = Table(title="Suspicious File Scan Results")

    table.add_column("File Path", justify="left", style="cyan")
    table.add_column("Extension", justify="center", style="green")
    table.add_column("Created Time", justify="center")
    table.add_column("Modified Time", justify="center")
    table.add_column("Size (bytes)", justify="right", style="magenta")
    table.add_column("Patterns Found", justify="left", style="yellow")

    for result in results:
        patterns = "\n".join(
            [f"[bold]{p['type']}[/bold] (Line {p['line']}) - {p['description']} ({p['impact']})" for p in result['patterns_found']]
        )
        table.add_row(
            result['file_path'],
            result['extension'],
            result['created_time'].strftime("%Y-%m-%d %H:%M:%S"),
            result['modified_time'].strftime("%Y-%m-%d %H:%M:%S"),
            str(result['size_in_bytes']),
            patterns
        )

    console.print(table)

# Fungsi utama
def main():
    parser = argparse.ArgumentParser(description="Scan files for potential backdoors and check with VirusTotal.")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-x", "--extensions", nargs="*", default=[], help="File extensions to scan (e.g., php py). Default: all extensions.")
    parser.add_argument("-s", "--save", help="File to save the scan report")
    args = parser.parse_args()

    directory_to_scan = args.directory
    extensions_to_scan = args.extensions

    console.log(f"Scanning directory: [bold]{directory_to_scan}[/bold]")
    if extensions_to_scan:
        console.log(f"Filtering by extensions: [bold]{', '.join(extensions_to_scan)}[/bold]")
    else:
        console.log("Scanning all file extensions.")

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
            console.log(f"Progress: [bold]{i}/{total_files}[/bold] files scanned")

    if suspicious_files:
        console.log("\n[bold red]Suspicious files found:[/bold red]")
        display_results(suspicious_files)

    if args.save:
        save_report(suspicious_files, args.save)

if __name__ == "__main__":
    main()
