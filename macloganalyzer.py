import re
import argparse
import sys

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
    # Dictionary to store parsed values
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
    
    # Regular expressions to capture key fields
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
    
    # Flag for backtrace collection (improved to handle multiple sections)
    collecting_backtrace = False

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.rstrip()
                # Try matching each defined field pattern
                for key, pattern in patterns.items():
                    match = pattern.match(line)
                    if match:
                        crash_info[key] = match.group(1)
                        break  # Move to the next line once a match is found

                # Start collecting backtrace lines when we see a thread header.
                # Some crash logs include "Thread X Crashed:" or similar markers.
                if re.match(r"^Thread\s+\d+\s+.*(Crashed|Triggered)", line):
                    collecting_backtrace = True
                    continue

                # Collect backtrace lines until a blank line or a new section header appears.
                if collecting_backtrace:
                    # Stop if we reach an empty line or a line that looks like a new section header
                    if line.strip() == "" or re.match(r"^\w+:", line):
                        collecting_backtrace = False
                    else:
                        crash_info["Backtrace"].append(line.strip())
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    return crash_info

def diagnose_crash(crash_info):
    """
    Provide a diagnosis based on the extracted crash log information.
    
    Parameters:
      crash_info (dict): The dictionary returned from parse_crash_log.
      
    Returns:
      str: A diagnostic message.
    """
    diagnosis = []
    diagnosis.append(f"Process: {crash_info.get('Process', 'N/A')}")
    diagnosis.append(f"Identifier: {crash_info.get('Identifier', 'N/A')}")
    diagnosis.append(f"Version: {crash_info.get('Version', 'N/A')}")
    diagnosis.append(f"OS Version: {crash_info.get('OS Version', 'N/A')}")
    diagnosis.append(f"Exception Type: {crash_info.get('Exception Type', 'N/A')}")
    diagnosis.append(f"Exception Codes: {crash_info.get('Exception Codes', 'N/A')}")
    diagnosis.append(f"Termination Reason: {crash_info.get('Termination Reason', 'N/A')}")
    diagnosis.append(f"Crashed Thread: {crash_info.get('Crashed Thread', 'N/A')}")
    diagnosis.append("")

    # Improved diagnostic logic inspired by common patterns in macOS crash reports:
    exception_type = crash_info.get("Exception Type", "")
    termination_reason = crash_info.get("Termination Reason", "")
    
    if "EXC_BAD_ACCESS" in exception_type:
        diagnosis.append("Diagnosis: The crash appears to be due to an EXC_BAD_ACCESS error, indicating invalid memory access. "
                         "This could be caused by dereferencing a null or invalid pointer.")
    elif "SIGABRT" in exception_type:
        diagnosis.append("Diagnosis: A SIGABRT signal was detected. This typically indicates that the process aborted due to an "
                         "assertion failure or critical internal error.")
    elif "EXC_CRASH" in exception_type:
        diagnosis.append("Diagnosis: An EXC_CRASH exception occurred. This suggests a fatal error or an unhandled exception leading "
                         "to an immediate termination of the process.")
    elif "EXC_ARITHMETIC" in exception_type:
        diagnosis.append("Diagnosis: The exception indicates an arithmetic error (e.g., division by zero). Check for any invalid "
                         "mathematical operations in your code.")
    else:
        diagnosis.append("Diagnosis: The exception type is not explicitly recognized. Further investigation of the backtrace and "
                         "additional log details is recommended.")

    # Additional hints based on Termination Reason
    if termination_reason and "Namespace" in termination_reason:
        diagnosis.append("Note: The termination reason suggests a namespace collision or resource conflict, which is a common "
                         "issue in macOS crash reports.")

    if crash_info["Backtrace"]:
        diagnosis.append("")
        diagnosis.append("Backtrace Summary (first 5 lines):")
        for line in crash_info["Backtrace"][:5]:
            diagnosis.append("  " + line)

    return "\n".join(diagnosis)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze a macOS crash log and provide an improved diagnosis based on common crash report fields."
    )
    parser.add_argument("filepath", type=str, help="Path to the macOS crash log file.")
    args = parser.parse_args()

    crash_info = parse_crash_log(args.filepath)
    diagnosis = diagnose_crash(crash_info)
    print(diagnosis)

if __name__ == "__main__":
    main()

