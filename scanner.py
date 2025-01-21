import os
import re
import argparse
import json
import time
import requests
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from fpdf import FPDF

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
console = Console()

# VirusTotal API Key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API URLs
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"


# Fungsi untuk memuat pola dari file JSON
def load_patterns(json_file):
    try:
        with open(json_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Gagal memuat pola dari file {json_file}: {e}")
        return {}


# Fungsi untuk memindai file berdasarkan pola mencurigakan
def scan_file(filepath, patterns):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.readlines()
            found_patterns = []

            for line_number, line in enumerate(content, start=1):
                for backdoor_type, details in patterns.items():
                    if re.search(details["pattern"], line):
                        found_patterns.append(
                            {
                                "type": backdoor_type,
                                "description": details["description"],
                                "impact": details["impact"],
                                "line": line_number,
                            }
                        )

            if found_patterns:
                return {
                    "file_path": filepath,
                    "patterns_found": found_patterns,
                    "extension": filepath.split(".")[-1],
                    "created_time": datetime.fromtimestamp(os.path.getctime(filepath)),
                    "modified_time": datetime.fromtimestamp(os.path.getmtime(filepath)),
                    "size_in_bytes": os.path.getsize(filepath),
                }
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
    return None


# Fungsi untuk upload file ke VirusTotal
def upload_file_to_virustotal(file_path):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (file_path, open(file_path, "rb"))}

    try:
        response = requests.post(UPLOAD_URL, headers=headers, files=files)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.warning(f"Gagal terhubung ke VirusTotal: {e}")
        return None


# Fungsi untuk mengecek status analisis file
def check_analysis_status(file_id):
    url = f"{ANALYSIS_URL}{file_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.warning(f"Gagal memeriksa status analisis: {e}")
        return None


# Fungsi untuk menunggu hasil analisis selesai
def wait_for_analysis_completion(file_id):
    while True:
        analysis_result = check_analysis_status(file_id)
        if analysis_result:
            status = analysis_result["data"]["attributes"]["status"]
            if status == "completed":
                return analysis_result
            console.log("Analisis belum selesai, menunggu 10 detik...")
            time.sleep(10)
        else:
            break


# Fungsi untuk menyimpan hasil scan ke dalam file JSON
def save_report(scan_results, save_path):
    try:
        report = []
        for result in scan_results:
            file_report = {
                "file_path": result["file_path"],
                "extension": result["extension"],
                "created_time": result["created_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "modified_time": result["modified_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "size_in_bytes": result["size_in_bytes"],
                "patterns_found": [
                    {
                        "type": pattern["type"],
                        "description": pattern["description"],
                        "impact": pattern["impact"],
                        "line": pattern["line"],
                    }
                    for pattern in result["patterns_found"]
                ],
            }

            if "virustotal" in result:
                file_report["virustotal"] = {
                    "is_safe": result["virustotal"]["is_safe"],
                    "malicious_count": result["virustotal"]["malicious_count"],
                    "analysis_link": result["virustotal"]["analysis_link"],
                }

            report.append(file_report)

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        console.log(
            f"[bold green]Laporan berhasil disimpan ke {save_path}[/bold green]"
        )
    except Exception as e:
        logging.error(f"Gagal menyimpan laporan: {e}")


# Fungsi untuk menyimpan hasil dalam format PDF
def save_report_pdf(scan_results, pdf_path):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="Scan Report", ln=True, align="C")
    pdf.ln(10)

    for result in scan_results:
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, txt=f"File: {result['file_path']}", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.cell(0, 10, txt=f"Extension: {result['extension']}", ln=True)
        pdf.cell(
            0,
            10,
            txt=f"Created: {result['created_time'].strftime('%Y-%m-%d %H:%M:%S')}",
            ln=True,
        )
        pdf.cell(
            0,
            10,
            txt=f"Modified: {result['modified_time'].strftime('%Y-%m-%d %H:%M:%S')}",
            ln=True,
        )
        pdf.cell(0, 10, txt=f"Size: {result['size_in_bytes']} bytes", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, txt="Patterns Found:", ln=True)
        pdf.set_font("Arial", size=11)
        for pattern in result["patterns_found"]:
            pdf.cell(
                0,
                10,
                txt=f"- {pattern['type']} (Line {pattern['line']}): {pattern['description']} ({pattern['impact']})",
                ln=True,
            )
        pdf.ln(5)

        if "virustotal" in result:
            vt = result["virustotal"]
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 10, txt="VirusTotal Analysis:", ln=True)
            pdf.set_font("Arial", size=11)
            pdf.cell(
                0, 10, txt=f"- Is Safe: {'Yes' if vt['is_safe'] else 'No'}", ln=True
            )
            pdf.cell(0, 10, txt=f"- Malicious Count: {vt['malicious_count']}", ln=True)
            pdf.cell(0, 10, txt=f"- Analysis Link: {vt['analysis_link']}", ln=True)
        pdf.ln(10)

    pdf.output(pdf_path)
    console.log(f"[bold green]Laporan PDF berhasil disimpan ke {pdf_path}[/bold green]")


# Fungsi utama
def main():
    parser = argparse.ArgumentParser(
        description="Scan files for potential backdoors and check with VirusTotal."
    )
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument(
        "-x",
        "--extensions",
        nargs="*",
        default=[],
        help="File extensions to scan (e.g., php py). Default: all extensions.",
    )
    parser.add_argument(
        "--patterns",
        default="patterns.json",
        help="JSON file containing suspicious patterns",
    )
    parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Check suspicious files with VirusTotal",
    )
    parser.add_argument("--save", help="File to save the scan report")
    parser.add_argument("--save-pdf", help="Path to save the scan report as a PDF")
    args = parser.parse_args()

    patterns = load_patterns(args.patterns)
    if not patterns:
        console.log("[bold red]Pola tidak ditemukan atau gagal dimuat.[/bold red]")
        return

    directory_to_scan = args.directory
    extensions_to_scan = args.extensions

    console.log(f"Scanning directory: [bold]{directory_to_scan}[/bold]")
    suspicious_files = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for root, _, files in os.walk(directory_to_scan):
            for file in files:
                if not extensions_to_scan or file.split(".")[-1] in extensions_to_scan:
                    filepath = os.path.join(root, file)
                    futures.append(executor.submit(scan_file, filepath, patterns))

        for future in futures:
            result = future.result()
            if result:
                suspicious_files.append(result)

    if suspicious_files:
        console.log("[bold red]Suspicious files found:[/bold red]")
        for suspicious_file in suspicious_files:
            console.print(suspicious_file)

        if args.virustotal:
            console.log("Checking suspicious files with VirusTotal...")
            for suspicious_file in suspicious_files:
                vt_result = upload_file_to_virustotal(suspicious_file["file_path"])
                if vt_result:
                    file_id = vt_result.get("data", {}).get("id")
                    if file_id:
                        final_result = wait_for_analysis_completion(file_id)
                        if final_result:
                            stats = final_result["data"]["attributes"]["stats"]
                            malicious_count = stats.get("malicious", 0)
                            is_safe = malicious_count == 0
                            file_hash = final_result["meta"]["file_info"]["sha256"]
                            analysis_link = (
                                f"https://www.virustotal.com/gui/file/{file_hash}"
                            )

                            suspicious_file["virustotal"] = {
                                "is_safe": is_safe,
                                "malicious_count": malicious_count,
                                "analysis_link": analysis_link,
                            }
                        else:
                            console.log(
                                f"[bold yellow]Skipping VirusTotal check for {suspicious_file['file_path']}[/bold yellow]"
                            )

    if args.save:
        save_report(suspicious_files, args.save)

    if args.save_pdf:
        save_report_pdf(suspicious_files, args.save_pdf)


if __name__ == "__main__":
    main()
