# macOS Crash Log Analyzer

A Python-based tool to parse and analyze macOS crash logs. This tool extracts key information from crash log files—such as process details, OS version, exception type, termination reason, and backtrace—and provides an improved diagnosis of potential causes. It is designed to help developers and support engineers quickly understand and debug crashes based on log data.

## Features

- **Enhanced Crash Log Parsing:**  
  The analyzer now extracts additional fields commonly found in macOS crash reports, including:
  - **Process:** Name of the crashed process.
  - **Identifier:** Bundle identifier of the process.
  - **Version:** Application version.
  - **OS Version:** The version of macOS running on the system.
  - **Exception Type & Exception Codes:** Details of the exception.
  - **Termination Reason:** Additional details about why the process terminated.
  - **Crashed Thread:** The thread number that caused the crash.
  - **Backtrace:** A detailed backtrace for further analysis.

- **Improved Diagnosis:**  
  Provides descriptive diagnostic messages based on:
  - Exception types (e.g., `EXC_BAD_ACCESS`, `SIGABRT`, `EXC_CRASH`, `EXC_ARITHMETIC`)
  - Termination reasons and hints found in macOS crash reports

- **Symbolication:**  
  Integrates with the `atos` tool to symbolicate backtraces, converting memory addresses into human-readable function names. (Requires providing the binary path and target architecture.)

- **Crash Clustering:**  
  Analyze and cluster multiple crash logs by Exception Type, summarizing common issues across logs.

- **Enhanced Error Handling & Output Formatting:**  
  - Specific exception handling for file errors (e.g., FileNotFoundError, PermissionError)
  - Output available in plain text (with ANSI color codes) or JSON format

- **Modularity & Extensibility:**  
  The code is structured to facilitate further modularization and integration with external libraries if desired.

## Getting Started

### Prerequisites

- **Python 3.6+**  
  Ensure you have Python installed. Download it from [python.org](https://www.python.org/).

- **macOS Environment:**  
  For symbolication, the `atos` tool (available on macOS) must be accessible in your PATH.

### Installation

1. **Clone the Repository:**
   
`git clone https://github.com/un1xr00t/macloganalyzer.git`
  <br />
`cd macloganalyzer`

   
2. **(Optional) Create and Activate a Virtual Environment:**

`python3 -m venv venv`
  <br />
`source venv/bin/activate`
   
## Usage

***Single Crash Log Analysis***
You can run the analyzer on a single macOS crash log file using one of these commands:

1. **Basic Analysis (No Symbolication):**

`python3 macloganalyzer.py /path/to/your/crash_log.log`

**What this does:**

Input: The path to your crash log file (/path/to/your/crash_log.log).
Operation: Parses the crash log using the default settings.
Output: Prints a plain text summary of the crash details and a diagnostic message based on the extracted information.
    
2. **Enhanced Analysis with Symbolication:**

`python3 macloganalyzer.py /path/to/your/crash_log.log --binary /path/to/your/binary --arch x86_64`

**What this does:**

Input: The path to your crash log file as before.
Additional Options:
--binary /path/to/your/binary: Specifies the path to the binary file associated with the crash log. This is used to symbolicate the backtrace, meaning that it will convert raw memory addresses into human-readable function names.
--arch x86_64: Specifies the architecture of the binary (e.g., x86_64 for Intel-based Macs or arm64 for Apple Silicon). This is needed for correct symbolication.
Operation: Parses the crash log and also attempts to symbolicate the backtrace using the provided binary and architecture.
Output: Prints a detailed summary that includes symbolicated backtrace entries, making it easier to understand the crash context.


**Output Options:**
Use --output json for JSON output or omit for plain text output.
