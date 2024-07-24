
# File Reputation Checker

## Overview

The **File Reputation Checker** is a comprehensive application designed to scan files in your Downloads directory, calculate their hashes, and check their reputations using the [VirusTotal API](https://www.virustotal.com). The application provides real-time insights into the potential risks of files by analyzing their hash values against VirusTotal's extensive database of threat intelligence.

## Features

- **Automatic Scanning**: Automatically scans files in your Downloads directory for any new additions.
  
- **Hash Calculation**: Utilizes SHA-256 to compute the file hash for reputation checks.
  
- **VirusTotal Integration**: Submits file hashes to VirusTotal and retrieves detailed reputation reports, including detection results from multiple antivirus engines.
  
- **Risk Assessment**: Calculates the risk percentage based on the number of detections from various antivirus scanners, providing a clear indication of potential threats.
  
- **Detailed Reporting**: Displays detailed analysis results, including additional file details such as MD5, SHA-1, SHA-256, SSDEEP, TLSH, Magic numbers, TrID, and submission dates.
  
- **Persistent Storage**: Saves scanned file information and hashes to prevent duplicate scanning and to maintain a historical record of scanned files.
  
- **Graphical User Interface (GUI)**: Easy-to-use GUI built with Tkinter, allowing users to refresh scans, view reputation results, and access historical data.

- **HTML Report Generation**: Generates HTML reports of scanned files, which can be opened in a browser for a detailed view of file reputation over time.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/file-reputation-checker.git
   cd file-reputation-checker
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Add your VirusTotal API keys in the `refresh()` function for file reputation checks.

## Usage

1. **Run the Application**:
   ```bash
   python file_reputation_checker.py
   ```

2. **Scan Files**:
   - Click the **Refresh** button to initiate a scan of files in your Downloads directory.
   - Newly scanned files and their reputation results will be displayed in the main window.

3. **View Historical Data**:
   - Click the **Old Files** button to view previously scanned files and their details.

4. **Generate Reports**:
   - Click **Open in Browser** to generate and view an HTML report of all scanned files.

## Screenshots

### Main Interface
![Main Interface](images/main_interface.png)

### Old Files Interface
![Old Files Interface](images/old_files_interface.png)

### HTML Report
![HTML Report](images/html_report.png)

## Contributions

Contributions are welcome! Please feel free to submit issues or pull requests.


This README provides a structured overview of your project, highlighting its main features and usage instructions, while making it accessible for potential contributors and users. 
