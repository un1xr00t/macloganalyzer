import re
import argparse
import sys

def parse_crash_log(file_path):
    """
    Parse a macOS crash log file to extract key information.

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
        "Exception Type": None,
        "Exception Codes": None,
        "Crashed Thread": None,
        "Backtrace": [],
    }
    
    # Regular expressions to capture key lines.
    patterns = {
        "Process": re.compile(r"^Process:\s+(.*)$"),
        "Identifier": re.compile(r"^Identifier:\s+(.*)$"),
        "Version": re.compile(r"^Version:\s+(.*)$"),
        "Exception Type": re.compile(r"^Exception Type:\s+(.*)$"),
        "Exception Codes": re.compile(r"^Exception Codes:\s+(.*)$"),
        "Crashed Thread": re.compile(r"^Crashed Thread:\s+(\d+)")
    }
    
    backtrace_collecting = False

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.rstrip()
                # Check for each field using regex
                for key, pattern in patterns.items():
                    match = pattern.match(line)
                    if match:
                        crash_info[key] = match.group(1)
                        break  # Move to next line if matched

                # Optionally, collect a simple backtrace section
                if line.startswith("Thread ") and "Crashed:" in line:
                    backtrace_collecting = True
                    continue

                if backtrace_collecting:
                    # In many crash logs, the backtrace is indented or numbered.
                    if line.strip() == "":
                        # Blank line marks end of backtrace section.
                        backtrace_collecting = False
                    else:
                        crash_info["Backtrace"].append(line.strip())
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    return crash_info

def diagnose_crash(crash_info):
    """
    Provide a simple diagnosis based on extracted crash log information.

    Parameters:
        crash_info (dict): The dictionary returned from parse_crash_log.

    Returns:
        str: A diagnostic message.
    """
    diagnosis = []
    exception_type = crash_info.get("Exception Type", "Unknown")
    exception_codes = crash_info.get("Exception Codes", "Unknown")
    
    diagnosis.append(f"Process: {crash_info.get('Process', 'N/A')}")
    diagnosis.append(f"Identifier: {crash_info.get('Identifier', 'N/A')}")
    diagnosis.append(f"Version: {crash_info.get('Version', 'N/A')}")
    diagnosis.append(f"Exception Type: {exception_type}")
    diagnosis.append(f"Exception Codes: {exception_codes}")
    diagnosis.append(f"Crashed Thread: {crash_info.get('Crashed Thread', 'N/A')}")
    diagnosis.append("")

    # Basic diagnosis logic based on common exception types.
    if "EXC_BAD_ACCESS" in exception_type:
        diagnosis.append("Diagnosis: This crash appears to be due to an EXC_BAD_ACCESS error. "
                         "This typically indicates that the application attempted to access invalid memory. "
                         "Possible causes include dereferencing null or dangling pointers, or use-after-free errors.")
    elif "SIGABRT" in exception_type:
        diagnosis.append("Diagnosis: The crash is related to a SIGABRT signal. "
                         "This usually means that the program aborted due to an internal error, assertion failure, or an explicit call to abort().")
    elif "EXC_CRASH" in exception_type:
        diagnosis.append("Diagnosis: An EXC_CRASH exception was raised. "
                         "This could be due to an unhandled exception, fatal runtime error, or a deliberate crash due to safety checks.")
    elif "EXC_ARITHMETIC" in exception_type:
        diagnosis.append("Diagnosis: The exception type indicates an arithmetic error. "
                         "This might be caused by division by zero or other illegal arithmetic operations.")
    else:
        diagnosis.append("Diagnosis: Exception type not specifically recognized. "
                         "Further manual analysis of the backtrace and surrounding log information may be required.")
    
    # You can add more detailed diagnosis by parsing the backtrace or other sections.
    if crash_info["Backtrace"]:
        diagnosis.append("")
        diagnosis.append("Backtrace Summary:")
        # Print the first few lines of the backtrace as a hint.
        for line in crash_info["Backtrace"][:5]:
            diagnosis.append("  " + line)

    return "\n".join(diagnosis)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze a macOS crash log and provide a diagnosis."
    )
    parser.add_argument(
        "filepath",
        type=str,
        help="Path to the macOS crash log file."
    )
    args = parser.parse_args()

    crash_info = parse_crash_log(args.filepath)
    diagnosis = diagnose_crash(crash_info)
    print(diagnosis)

if __name__ == "__main__":
    main()
