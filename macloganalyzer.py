import re
import argparse
import sys
import json
import subprocess
import os

def parse_crash_log(file_path):
    """
    Parse a macOS crash log file to extract key information.

    Inspired by:
    https://appleinsider.com/inside/macos/tips/how-to-understand-macos-finder-crash-report-alerts

    Parameters:
      file_path (str): The path to the crash log file.

    Returns:
      dict: A dictionary with extracted fields.
    """
    crash_info = {
        "Process": None,
        "Identifier": None,
        "Version": None,
        "OS Version": None,
        "Exception Type": None,
        "Exception Codes": None,
        "Termination Reason": None,
        "Crashed Thread": None,
        "Backtrace": [],
    }
    
    # Define regular expressions for key fields
    patterns = {
        "Process": re.compile(r"^Process:\s+(.*)$"),
        "Identifier": re.compile(r"^Identifier:\s+(.*)$"),
        "Version": re.compile(r"^Version:\s+(.*)$"),
        "OS Version": re.compile(r"^OS Version:\s+(.*)$"),
        "Exception Type": re.compile(r"^Exception Type:\s+(.*)$"),
        "Exception Codes": re.compile(r"^Exception Codes:\s+(.*)$"),
        "Termination Reason": re.compile(r"^Termination Reason:\s+(.*)$"),
        "Crashed Thread": re.compile(r"^Crashed Thread:\s+(\d+)"),
    }
    
    # Flag for collecting backtrace lines
    collecting_backtrace = False

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.rstrip()

                # Attempt to match each key field
                for key, pattern in patterns.items():
                    match = pattern.match(line)
                    if match:
                        crash_info[key] = match.group(1)
                        break

                # Determine when to start collecting backtrace lines
                if re.match(r"^Thread\s+\d+\s+.*(Crashed|Triggered)", line):
                    collecting_backtrace = True
                    continue

                # Collect backtrace lines until a blank line or a new section header is encountered
                if collecting_backtrace:
                    if line.strip() == "" or re.match(r"^\w+:", line):
                        collecting_backtrace = False
                    else:
                        crash_info["Backtrace"].append(line.strip())
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading '{file_path}': {e}")
        sys.exit(1)

    return crash_info

def symbolicate_backtrace(backtrace, binary, arch):
    """
    Convert memory addresses in the backtrace into symbolicated function names using `atos`.

    Parameters:
      backtrace (list): A list of backtrace lines.
      binary (str): The path to the binary to symbolicate against.
      arch (str): The architecture (e.g., "x86_64" or "arm64").

    Returns:
      list: A new backtrace list with symbolicated entries.
    """
    symbolicated = []
    # Regex to match hex addresses (e.g., 0x7fff12345678)
    addr_pattern = re.compile(r"(0x[0-9A-Fa-f]+)")
    
    for line in backtrace:
        matches = addr_pattern.findall(line)
        if matches and os.path.exists(binary):
            for addr in matches:
                try:
                    # Call atos to symbolicate the address.
                    result = subprocess.run(
                        ["atos", "-o", binary, "-arch", arch, addr],
                        capture_output=True, text=True, check=True
                    )
                    symbol = result.stdout.strip()
                    if symbol:
                        # Replace the address with the symbolicated output.
                        line = line.replace(addr, symbol)
                except subprocess.CalledProcessError:
                    # If atos fails, leave the address unchanged.
                    continue
        symbolicated.append(line)
    return symbolicated

def diagnose_crash(crash_info, binary=None, arch="x86_64"):
    """
    Provide a detailed diagnosis based on the extracted crash log information.
    Optionally, symbolicate the backtrace if binary and arch are provided.

    Parameters:
      crash_info (dict): The dictionary returned from parse_crash_log.
      binary (str): Optional; path to the binary for symbolication.
      arch (str): Optional; architecture for symbolication.
      
    Returns:
      dict: A dictionary containing the diagnosis and suggestions.
    """
    
    diagnosis = {}
    diagnosis['Summary'] = {
        "Process": crash_info.get("Process", "N/A"),
        "Identifier": crash_info.get("Identifier", "N/A"),
        "Version": crash_info.get("Version", "N/A"),
        "OS Version": crash_info.get("OS Version", "N/A"),
        "Exception Type": crash_info.get("Exception Type", "N/A"),
        "Exception Codes": crash_info.get("Exception Codes", "N/A"),
        "Termination Reason": crash_info.get("Termination Reason", "N/A"),
        "Crashed Thread": crash_info.get("Crashed Thread", "N/A")
    }
    
    def diagnose_crash(crash_info, binary=None, arch="x86_64"):
    diagnosis = {}
    diagnosis['Summary'] = {
        "Process": crash_info.get("Process", "N/A"),
        "Identifier": crash_info.get("Identifier", "N/A"),
        "Version": crash_info.get("Version", "N/A"),
        "OS Version": crash_info.get("OS Version", "N/A"),
        "Exception Type": crash_info.get("Exception Type", "N/A"),
        "Exception Codes": crash_info.get("Exception Codes", "N/A"),
        "Termination Reason": crash_info.get("Termination Reason", "N/A"),
        "Crashed Thread": crash_info.get("Crashed Thread", "N/A")
    }
    
    detailed_diagnosis = []
    # Ensure these variables are strings even if the original value is None
    exception_type = crash_info.get("Exception Type") or ""
    termination_reason = crash_info.get("Termination Reason") or ""

    if "EXC_BAD_ACCESS" in exception_type:
        detailed_diagnosis.append("EXC_BAD_ACCESS indicates invalid memory access. Check for null or dangling pointers.")
    elif "SIGABRT" in exception_type:
        detailed_diagnosis.append("SIGABRT suggests the process aborted, potentially due to an assertion failure or a critical internal error.")
    elif "EXC_CRASH" in exception_type:
        detailed_diagnosis.append("EXC_CRASH points to a fatal error or unhandled exception causing an immediate termination.")
    elif "EXC_ARITHMETIC" in exception_type:
        detailed_diagnosis.append("EXC_ARITHMETIC hints at an arithmetic error (e.g., division by zero). Verify all mathematical operations.")
    else:
        detailed_diagnosis.append("The exception type is not explicitly recognized. Further investigation of the backtrace may be required.")

    if termination_reason and "Namespace" in termination_reason:
        detailed_diagnosis.append("Termination Reason suggests a potential namespace collision or resource conflict.")

    diagnosis['Detailed'] = detailed_diagnosis

    backtrace = crash_info.get("Backtrace", [])
    if binary:
        backtrace = symbolicate_backtrace(backtrace, binary, arch)
    diagnosis['Backtrace Summary'] = backtrace[:5]  # First 5 lines
    
    return diagnosis

def report_diagnosis(diagnosis, output_format="plain"):
    """
    Report the diagnosis in the desired format.

    Parameters:
      diagnosis (dict): The diagnosis information to report.
      output_format (str): The output format ("plain" or "json").

    Returns:
      None
    """
    if output_format == "json":
        print(json.dumps(diagnosis, indent=4))
    else:
        # Plain text output with simple formatting and ANSI color codes.
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        summary = diagnosis.get("Summary", {})
        print(f"{GREEN}Crash Report Summary:{RESET}")
        for key, value in summary.items():
            print(f"{YELLOW}{key}:{RESET} {value}")
        print("\n" + f"{GREEN}Detailed Diagnosis:{RESET}")
        for line in diagnosis.get("Detailed", []):
            print(f"- {line}")
        print("\n" + f"{GREEN}Backtrace Summary (first 5 lines):{RESET}")
        for line in diagnosis.get("Backtrace Summary", []):
            print(f"  {line}")

def cluster_crashes(file_paths, output_format="plain"):
    """
    Cluster multiple crash logs based on their Exception Type and report summary statistics.

    Parameters:
      file_paths (list): List of file paths to crash log files.
      output_format (str): The output format ("plain" or "json").

    Returns:
      None
    """
    clusters = {}
    for file_path in file_paths:
        crash_info = parse_crash_log(file_path)
        key = crash_info.get("Exception Type", "Unknown")
        clusters.setdefault(key, []).append(crash_info)
    
    # Prepare a summary of clusters
    cluster_summary = {}
    for exception_type, crashes in clusters.items():
        cluster_summary[exception_type] = {
            "Number of Crashes": len(crashes),
            "Processes": list({crash.get("Process", "N/A") for crash in crashes}),
            "OS Versions": list({crash.get("OS Version", "N/A") for crash in crashes})
        }
    
    if output_format == "json":
        print(json.dumps(cluster_summary, indent=4))
    else:
        print("Crash Clusters Summary:")
        for exception_type, summary in cluster_summary.items():
            print(f"\nException Type: {exception_type}")
            print(f"  Number of Crashes: {summary['Number of Crashes']}")
            print(f"  Processes: {', '.join(summary['Processes'])}")
            print(f"  OS Versions: {', '.join(summary['OS Versions'])}")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced macOS Crash Log Analyzer with symbolication and crash clustering."
    )
    # When clustering, allow multiple file paths; otherwise, expect one file.
    parser.add_argument("filepaths", nargs="*", help="Paths to macOS crash log file(s). Provide multiple files for clustering.")
    parser.add_argument("--output", choices=["plain", "json"], default="plain",
                        help="Output format for the diagnosis (default: plain).")
    parser.add_argument("--binary", type=str, default=None,
                        help="Path to the binary for symbolication (optional).")
    parser.add_argument("--arch", type=str, default="x86_64",
                        help="Architecture for symbolication (default: x86_64).")
    parser.add_argument("--cluster", action="store_true",
                        help="Enable clustering mode to analyze multiple crash logs.")

    args = parser.parse_args()

    if args.cluster:
        if not args.filepaths:
            print("Error: Please provide at least one crash log file for clustering.")
            sys.exit(1)
        cluster_crashes(args.filepaths, args.output)
    else:
        if not args.filepaths or len(args.filepaths) != 1:
            print("Error: Please provide exactly one crash log file for analysis.")
            sys.exit(1)
        crash_info = parse_crash_log(args.filepaths[0])
        diagnosis = diagnose_crash(crash_info, binary=args.binary, arch=args.arch)
        report_diagnosis(diagnosis, args.output)

    # Future enhancements could include more advanced crash clustering algorithms
    # and integrating with external crash report libraries for deeper analysis.

if __name__ == "__main__":
    main()

