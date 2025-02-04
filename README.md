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
Run the analyzer by providing the path to a single macOS crash log file. Optionally, provide the binary path and architecture for symbolication:

`python3 macloganalyzer.py /path/to/your/crash_log.log`
<br />
`python3 crash_log_analyzer.py /path/to/your/crash_log.log --binary /path/to/your/binary --arch x86_64`


Output Options:
Use --output json for JSON output or omit for plain text output.
